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

// MARK: - Bio UV Tests

@Suite("Bio UV", .serialized)
struct BioUVTests {

    @Test("Create credential using UV token")
    func testMakeCredentialWithUVToken() async throws {
        try await withEnrolledFingerprint { session, templateId in
            // Get UV token via fingerprint (not PIN) with makeCredential permission
            print("👆 Touch enrolled fingerprint to get UV token...")
            let uvToken = try await session.getUVToken(
                permissions: [.makeCredential],
                rpId: "example.com"
            )

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: Data(repeating: 0xCD, count: 32),
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: "example.com", name: "Example"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x10, count: 32),
                    name: "uv-user@example.com",
                    displayName: "UV User"
                ),
                pubKeyCredParams: [.es256],
                rk: true
            )

            print("👆 Touch enrolled fingerprint to create credential...")
            let credential = try await session.makeCredential(
                parameters: params,
                uvToken: uvToken
            ).value

            // UV token should set BOTH UV and UP flags
            #expect(credential.authenticatorData.flags.contains(.userPresent))
            #expect(credential.authenticatorData.flags.contains(.userVerified))
            print("✅ Credential created with UV token (UP + UV flags set)")
        }
    }

    @Test("UV blocking after wrong fingerprint attempts")
    func testUVBlocking() async throws {
        try await withEnrolledFingerprint { session, templateId in
            // Attempt to get UV token 3 times with WRONG fingerprint
            // This should cause UV_BLOCKED error
            print("\n⚠️  Next 3 attempts: Use a DIFFERENT fingerprint (not the enrolled one)")

            for attempt in 1...3 {
                do {
                    print("👆 Attempt \(attempt)/3: Touch WRONG fingerprint...")
                    _ = try await session.getUVToken(
                        permissions: [.makeCredential],
                        rpId: "example.com"
                    )
                    Issue.record("Wrong fingerprint should have been rejected")
                } catch let error as CTAP2.SessionError {
                    if case .ctapError(let code, _) = error {
                        if attempt < 3 {
                            #expect(code == .uvInvalid, "Expected uvInvalid on attempt \(attempt), got: \(code)")
                            print("✅ Received UV_INVALID (\(attempt)/3)")
                        } else {
                            #expect(code == .uvBlocked, "Expected uvBlocked on attempt 3, got: \(code)")
                            print("✅ Received UV_BLOCKED after 3 failed attempts")
                        }
                    } else {
                        Issue.record("Expected CTAP error, got: \(error)")
                    }
                }
            }

            // Now verify that PIN still works even though UV is blocked
            print("\n👆 Touch sensor for user presence (PIN will be used, not UV)...")
            let pinToken = try await session.getPinToken(
                defaultTestPin,
                permissions: [.makeCredential],
                rpId: "example.com"
            )

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: Data(repeating: 0xCD, count: 32),
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: "example.com", name: "Example"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x01, count: 32),
                    name: "pin-user@example.com",
                    displayName: "PIN User"
                ),
                pubKeyCredParams: [.es256],
                rk: true
            )

            let credential = try await session.makeCredential(
                parameters: params,
                pinToken: pinToken
            ).value

            // PIN token with uv: nil → authenticator sets UP but not UV
            #expect(credential.authenticatorData.flags.contains(.userPresent))
            #expect(!credential.authenticatorData.flags.contains(.userVerified))
            print("✅ PIN works even with UV blocked (UP set, UV not set)")
        }
    }
}

// MARK: - Test Fixture

/// Helper that enrolls a fingerprint and provides it to the test body
private func withEnrolledFingerprint(
    _ body: (CTAP2.Session, Data) async throws -> Void
) async throws {
    try await withCTAP2Session { session in
        guard try await CTAP2.BioEnrollment.isSupported(by: session) else {
            print("Bio enrollment not supported - skipping")
            return
        }

        let info = try await session.getInfo()
        guard info.options.clientPin == true else {
            print("PIN not set - skipping")
            return
        }

        // Get PIN token for bio enrollment management
        let pinToken = try await session.getPinToken(
            defaultTestPin,
            permissions: [.bioEnrollment]
        )
        let bio = try await session.bioEnrollment(pinToken: pinToken)

        // Clean up any existing enrollments
        let existing = try await bio.enrollments.enumerate()
        for template in existing {
            try await bio.removeEnrollment(template.templateId)
        }

        // Enroll a fingerprint
        var templateId: Data?
        print("👆 Press fingerprint against the sensor to enroll...")
        for try await sample in bio.enroll() {
            switch sample {
            case .waitingForUser:
                print("👆 Touch the sensor...")
            case .sample(let status, let remaining):
                if status == .good {
                    print("✅ \(remaining) more scans needed")
                } else {
                    print("⚠️  \(status)")
                }
            case .completed(let id, _):
                templateId = id
            }
        }

        guard let enrolledTemplateId = templateId else {
            Issue.record("Failed to enroll fingerprint")
            return
        }

        #expect(try await bio.enrollments.enumerate().count == 1)
        print("✅ Fingerprint enrolled successfully")

        // Run the test body
        try await body(session, enrolledTemplateId)

        // Clean up
        try await bio.removeEnrollment(enrolledTemplateId)
        #expect(try await bio.enrollments.enumerate().isEmpty)
        print("✅ Fingerprint removed")
    }
}

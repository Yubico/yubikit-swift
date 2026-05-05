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
            let uvToken = try await session.getPinUVToken(
                using: .uv,
                permissions: [.makeCredential],
                rpId: "example.com"
            )

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: Data(repeating: 0xCD, count: 32),
                rp: WebAuthn.RelyingParty(id: "example.com", name: "Example"),
                user: WebAuthn.User(
                    id: Data(repeating: 0x10, count: 32),
                    name: "uv-user@example.com",
                    displayName: "UV User"
                ),
                pubKeyCredParams: [.es256],
                rk: true
            )

            let credential = try await session.makeCredential(
                parameters: params,
                token: uvToken
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
            // Attempt UV with wrong fingerprint until the authenticator blocks UV.
            // The retry threshold is authenticator-specific (typically 3–5).
            let maxAttempts = 10
            print("\n⚠️  Use a DIFFERENT fingerprint (not the enrolled one) until UV is blocked")

            var attempt = 0
            while attempt < maxAttempts {
                attempt += 1
                do {
                    print("👆 Attempt \(attempt): Touch WRONG fingerprint...")
                    _ = try await session.getPinUVToken(
                        using: .uv,
                        permissions: [.makeCredential],
                        rpId: "example.com"
                    )
                    Issue.record("Wrong fingerprint should have been rejected")
                } catch let error as CTAP2.SessionError {
                    if case .ctapError(let code, _) = error {
                        if code == .uvBlocked {
                            print("✅ UV_BLOCKED after \(attempt) failed attempts")
                            break
                        }
                        #expect(code == .uvInvalid, "Expected uvInvalid on attempt \(attempt), got: \(code)")
                        print("✅ UV_INVALID (\(attempt))")
                    } else {
                        Issue.record("Expected CTAP error, got: \(error)")
                    }
                }
            }
            #expect(attempt <= maxAttempts, "UV was not blocked after \(maxAttempts) attempts")

            // Now verify that PIN still works even though UV is blocked
            print("\n👆 Touch sensor for user presence (PIN will be used, not UV)...")
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: "example.com"
            )

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: Data(repeating: 0xCD, count: 32),
                rp: WebAuthn.RelyingParty(id: "example.com", name: "Example"),
                user: WebAuthn.User(
                    id: Data(repeating: 0x01, count: 32),
                    name: "pin-user@example.com",
                    displayName: "PIN User"
                ),
                pubKeyCredParams: [.es256],
                rk: true
            )

            let credential = try await session.makeCredential(
                parameters: params,
                token: pinToken
            ).value

            // Per CTAP 2.2 §6.1.1: valid pinUvAuthParam sets UV flag regardless of token type
            #expect(credential.authenticatorData.flags.contains(.userPresent))
            #expect(credential.authenticatorData.flags.contains(.userVerified))
            print("✅ PIN works even with UV blocked (UP + UV flags set)")
        }
    }
}

// MARK: - Test Fixture

/// Helper that enrolls a fingerprint and provides it to the test body
private func withEnrolledFingerprint(
    _ body: (CTAP2.Session, Data) async throws -> Void
) async throws {
    try await withCTAP2Session { session in
        try #require(await CTAP2.BioEnrollment.isSupported(by: session), "Bio enrollment not supported")

        let info = try await session.getInfo()
        try #require(info.options.clientPin == true, "PIN not set")

        // Get PIN token for bio enrollment management
        let pinToken = try await session.getPinUVToken(
            using: .pin(defaultTestPin),
            permissions: [.bioEnrollment]
        )
        let bio = try await session.bioEnrollment(token: pinToken)

        // Clean up any existing enrollments
        let existing = try await bio.enrollments.enumerate()
        for template in existing {
            try await bio.removeEnrollment(template.templateId)
        }

        // Enroll a fingerprint
        var templateId: Data?
        print("👆 Starting enrollment...")
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

        let enrolledTemplateId = try #require(templateId, "Failed to enroll fingerprint")

        #expect(try await bio.enrollments.enumerate().count == 1)
        print("✅ Fingerprint enrolled successfully")

        // Run the test body
        try await body(session, enrolledTemplateId)

        // Re-obtain PIN token for cleanup (test body may have invalidated the original token)
        let cleanupToken = try await session.getPinUVToken(
            using: .pin(defaultTestPin),
            permissions: [.bioEnrollment]
        )
        let cleanupBio = try await session.bioEnrollment(token: cleanupToken)

        // Clean up
        try await cleanupBio.removeEnrollment(enrolledTemplateId)
        #expect(try await cleanupBio.enrollments.enumerate().isEmpty)
        print("✅ Fingerprint removed")
    }
}

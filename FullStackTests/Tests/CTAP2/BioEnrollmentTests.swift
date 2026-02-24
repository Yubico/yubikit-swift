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

// MARK: - Bio Enrollment Tests

@Suite("Bio Enrollment", .serialized)
struct BioEnrollmentTests {

    @Test("Get fingerprint sensor info")
    func testGetSensorInfo() async throws {
        try await withBioEnrollment { bio in
            let info = try await bio.getFingerprintSensorInfo()
            // fingerprintKind should be 'touch' or 'swipe'
            #expect([.touch, .swipe].contains(info.fingerprintKind))
            // maxCaptureSamplesRequired should be > 0
            #expect(info.maxCaptureSamplesRequired > 0)
            // maxTemplateFriendlyName should be > 0 if present
            if let maxName = info.maxTemplateFriendlyName {
                #expect(maxName > 0)
            }
        }
    }

    @Test("Enroll, rename, and delete fingerprint")
    func testEnrollRenameDelete() async throws {
        try await withBioEnrollment { bio in
            // Remove all existing enrollments
            let existing = try await bio.enrollments.enumerate()
            for template in existing {
                try await bio.removeEnrollment(template.templateId)
            }

            // Verify we start with no enrollments
            #expect(try await bio.enrollments.enumerate().isEmpty)

            // Enroll fingerprint
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

            #expect(templateId != nil)

            // Check enrollment exists with no name
            var enrollments = try await bio.enrollments.enumerate()
            #expect(enrollments.count == 1)
            #expect(enrollments[0].templateId == templateId)
            #expect(enrollments[0].friendlyName == nil || enrollments[0].friendlyName == "")

            // Set name
            try await bio.setFriendlyName("Test 1", for: templateId!)
            enrollments = try await bio.enrollments.enumerate()
            #expect(enrollments.count == 1)
            #expect(enrollments[0].friendlyName == "Test 1")

            // Set name to max length
            let sensorInfo = try await bio.getFingerprintSensorInfo()
            if let maxLen = sensorInfo.maxTemplateFriendlyName {
                let maxName = "Test" + String(repeating: "!", count: Int(maxLen) - 4)
                try await bio.setFriendlyName(maxName, for: templateId!)
                enrollments = try await bio.enrollments.enumerate()
                #expect(enrollments.count == 1)
                #expect(enrollments[0].friendlyName == maxName)

                // Test max length + 1 error
                let tooLongName = "Test" + String(repeating: "!", count: Int(maxLen) - 3)
                do {
                    try await bio.setFriendlyName(tooLongName, for: templateId!)
                    Issue.record("Should have thrown error for name exceeding max length")
                } catch let error as CTAP2.SessionError {
                    guard case .ctapError(.invalidLength, _) = error else {
                        Issue.record("Expected invalidLength error, got: \(error)")
                        return
                    }
                    print("✅ Correctly rejected name exceeding max length with invalidLength error")
                }
            }

            // Delete fingerprint
            try await bio.removeEnrollment(templateId!)
            #expect(try await bio.enrollments.enumerate().isEmpty)
        }
    }
}

// MARK: - Test Fixture

private func withBioEnrollment(
    _ body: (CTAP2.BioEnrollment) async throws -> Void
) async throws {
    try await withCTAP2Session { session in
        try #require(await CTAP2.BioEnrollment.isSupported(by: session), "Bio enrollment not supported")

        let info = try await session.getInfo()
        try #require(info.options.clientPin == true, "PIN not set")

        let pinToken = try await session.getPinUVToken(
            using: .pin(defaultTestPin),
            permissions: [.bioEnrollment]
        )

        let bio = try await session.bioEnrollment(token: pinToken)

        try await body(bio)
    }
}

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

    // MARK: - Helper Methods

    #if os(macOS)
    private func withCTAP2Session<T>(
        _ body: (FIDO2Session) async throws -> T
    ) async throws -> T {
        let connection = try await HIDFIDOConnection.makeConnection()
        let session = try await CTAP.Session.makeSession(connection: connection)
        return try await body(session)
    }
    #elseif os(iOS)
    private func withCTAP2Session<T>(
        _ body: (FIDO2SessionOverSmartCard) async throws -> T
    ) async throws -> T {
        let connection = try await TestableConnection.create(with: .nfc)
        let session = try await CTAP.Session.makeSession(connection: connection)
        return try await body(session)
    }
    #endif
}

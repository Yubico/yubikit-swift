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

/// Session construction over each transport, mirroring yubikit-android's `YubiOtpSessionTest`.
/// Over SmartCard the status struct arrives in the SELECT response rather than from a status
/// report, so the version and config state come from a different place than on the OTP transport.
struct YubiOTPSessionTests {

    /// `version[3] ‖ pgmSeq[1] ‖ configState[2, LE]`, then SW=0x9000.
    private static func selectResponse(_ status: [UInt8]) -> Data {
        Data(status) + Data([0x90, 0x00])
    }

    @Test("opening over SmartCard selects the OTP application and parses the status struct")
    func opensOverSmartCard() async throws {
        // Slot 1 configured, slot 2 not: configState 0x0001, little-endian.
        let mock = MockSmartCardConnection(responses: [Self.selectResponse([5, 7, 0, 3, 0x01, 0x00])])

        let session = try await YubiOTP.Session.makeSession(connection: mock)

        #expect(await session.version == Version(withData: Data([5, 7, 0])))
        #expect(await session.configState.isConfigured(.one))
        #expect(!(await session.configState.isConfigured(.two)))

        // A single SELECT of the OTP AID, and nothing else.
        let requests = await mock.sentRequests
        #expect(requests.count == 1)
        #expect(
            requests[0] == Data([0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01]),
            "expected SELECT of the OTP AID, got \(requests[0].hexEncodedString)"
        )
    }

    @Test("opening over the OTP transport parses the status struct from the status report")
    func opensOverOTP() async throws {
        let connection = try await FakeOTPConnection()
        connection.firmware = [5, 7, 0]

        let session = try await YubiOTP.Session.makeSession(connection: connection)

        #expect(await session.version == Version(withData: Data([5, 7, 0])))
    }
}

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

@Suite(.serialized)
struct ManagementSessionTests {
    @Test("OTP device info rejects invalid lengths and CRCs", arguments: [false, true])
    func invalidOTPDeviceInfo(badLength: Bool) async throws {
        let connection = try await FakeOTPConnection()
        connection.managementResponse = badLength ? Data([9, 0x02, 4, 0, 0]) : Data([5, 0x05, 3, 5, 7, 4])
        connection.corruptsResponseCRC = !badLength
        let otp = try await OTPKeyboardInterface<ManagementSessionError>(connection: connection)
        let interface = Management.Session.Interface(interface: otp)
        await #expect { try await interface.readConfig(page: 0) } throws: {
            guard case ManagementSessionError.responseParseError = $0 else { return false }
            return true
        }
    }

    @Test("OTP device reset is rejected before sending a command")
    func resetRequiresSmartCard() async throws {
        let connection = try await FakeOTPConnection()
        let session = try await Management.Session.makeSession(connection: connection)
        await #expect { try await session.resetDevice() } throws: {
            guard case ManagementSessionError.featureNotSupported = $0 else { return false }
            return true
        }
        #expect(connection.dispatchedCommands.isEmpty)
    }

    @Test("OTP Management resolves this development key rather than a cached version")
    func developmentVersion() async throws {
        let previous = Version.developmentOverride
        defer { Version.developmentOverride = previous }
        Version.developmentOverride = Version("5.7.4")!
        let connection = try await FakeOTPConnection()
        connection.firmware = [0, 0, 1]
        // DeviceInfo firmware 0.0.1 with a 5.8.0 version qualifier.
        let tlvs = Data([0x05, 3, 0, 0, 1, 0x19, 5, 0x01, 3, 5, 8, 0])
        connection.managementResponse = Data([UInt8(tlvs.count)]) + tlvs

        let session = try await Management.Session.makeSession(connection: connection)
        #expect(await session.version == Version("5.8.0")!)
        #expect(connection.dispatchedCommands == [0x13])
    }
}

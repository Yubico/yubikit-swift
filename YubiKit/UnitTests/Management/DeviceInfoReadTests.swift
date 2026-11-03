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

struct DeviceInfoReadTests {
    private let ok = Data([0x90, 0])
    private let missing = Data([0x6a, 0x82])

    @Test("Management information is preferred without probing other applications")
    func management() async throws {
        let tlvs = Data([4, 1, 3, 0x1b, 3]) + Data("Key".utf8)
        let connection = MockSmartCardConnection(responses: [Data("5.8.0".utf8) + ok, page(tlvs) + ok])
        let name = try await connection.deviceName
        #expect(name == "Key")
        #expect(await connection.sendCount == 2)
    }

    @Test("Legacy smart cards reconstruct information without a USB PID")
    func legacySmartCard() async throws {
        let connection = MockSmartCardConnection(responses: [
            missing, Data([3, 4, 3, 0, 0, 0]) + ok, Data([0, 0, 0, 123]) + ok,
            ok, ok, ok, ok,
        ])
        let info = try await DeviceInfo.read(connection: connection)
        #expect(info.deviceName == "YubiKey NEO")
        #expect(info.version == Version("3.4.3")!)
        #expect(info.serialNumber == 123)
        #expect(info.formFactor == .unknown)
        #expect(info.reportedName == nil)
        #expect(info.hasTransport(.nfc))
        #expect(info.isApplicationSupported(.openPGP, over: .usb))
        #expect(info.config.enabledCapabilities.isEmpty)
        let requests = await connection.sentRequests
        #expect(requests.count == 7)
        #expect(requests[2][1] == 1)  // Serial read; other requests select applications.
    }

    @Test("Pre-4.1 Management firmware falls back without issuing READ CONFIG")
    func oldManagement() async throws {
        let connection = MockSmartCardConnection(responses: [
            Data("3.4.0".utf8) + ok, Data([3, 4, 3, 0, 0, 0]) + ok, missing,
            missing, ok, ok, ok, missing,
        ])
        let info = try await DeviceInfo.read(connection: connection)
        #expect(info.deviceName == "YubiKey NEO")
        #expect(info.version == Version("3.4.3")!)
        #expect(info.serialNumber == 0)
        #expect(await connection.sentRequests.allSatisfy { $0[1] != 0x1d })
    }

    @Test("Application probing works when OTP is unavailable")
    func withoutOTP() async throws {
        let connection = MockSmartCardConnection(responses: [missing, missing, missing, missing, missing, ok, missing])
        let info = try await DeviceInfo.read(connection: connection)
        #expect(info.deviceName == "YubiKey NEO")
        #expect(info.serialNumber == 0)
        #expect(info.isApplicationSupported(.oath, over: .usb))
    }

    @Test("Legacy Yubico U2F applets are probed when the standard FIDO AID is absent")
    func legacyU2FApplet() async throws {
        let connection = MockSmartCardConnection(responses: [
            missing, Data([3, 2, 0, 0, 0, 0]) + ok, Data([0, 0, 0, 123]) + ok,
            missing, ok, ok, ok, ok,
        ])
        let info = try await DeviceInfo.read(connection: connection)
        #expect(info.deviceName == "YubiKey NEO")
        #expect(info.isApplicationSupported(.u2f, over: .usb))
        #expect(await connection.sentRequests.last?.suffix(7) == Data([0xa0, 0, 0, 5, 0x27, 0x10, 2]))
    }

    @Test("Generic PIV and FIDO applets do not establish Yubico identity", arguments: [Capability.piv, .u2f])
    func genericApplets(capability: Capability) async throws {
        let connection = MockSmartCardConnection(responses: [
            missing, missing, capability == .u2f ? ok : missing, capability == .piv ? ok : missing,
            missing, missing, missing,
        ])
        await #expect(throws: ManagementSessionError.self) { try await connection.deviceName }
    }

    @Test(
        "Management errors do not trigger legacy probing",
        arguments: [
            Data([0x69, 0x82]), Data([0x90, 0]), Data([0]),
        ]
    )
    func managementErrors(response: Data) async throws {
        let connection = MockSmartCardConnection(responses: [response])
        await #expect(throws: ManagementSessionError.self) { try await connection.deviceName }
        #expect(await connection.sendCount == 1)
    }

    @Test("Malformed Management data does not trigger legacy probing")
    func malformedDeviceInfo() async throws {
        let connection = MockSmartCardConnection(responses: [Data("5.8.0".utf8) + ok, Data([0]) + ok])
        await #expect(throws: ManagementSessionError.self) { try await connection.deviceName }
        #expect(await connection.sendCount == 2)
    }

    @Test("Application probe errors are propagated")
    func probeErrors() async throws {
        let connection = MockSmartCardConnection(responses: [missing, missing, Data([0x69, 0x82])])
        await #expect(throws: ManagementSessionError.self) { try await connection.deviceName }
        #expect(await connection.sendCount == 3)
    }

    @Test("OTP serial parsing errors are propagated")
    func serialErrors() async throws {
        let connection = MockSmartCardConnection(responses: [missing, Data([3, 4, 3, 0, 0, 0]) + ok, ok])
        await #expect(throws: YubiOTP.SessionError.self) { try await connection.deviceName }
        #expect(await connection.sendCount == 3)
    }

    @Test("OTP HID reads paginated Management information")
    func otpManagement() async throws {
        let connection = try await FakeOTPConnection()
        connection.deviceInfoPages = [page(Data([4, 1, 3, 0x10, 1, 1])), page(Data([0x1b, 3]) + Data("Key".utf8))]
        let name = try await connection.deviceName
        #expect(name == "Key")
        #expect(connection.dispatchedCommands == [0x13, 0x13])
        #expect(connection.dispatchedPayloads.map { $0.first! } == [0, 1])
    }

    @Test("OTP HID rejects corrupt Management responses")
    func otpCRC() async throws {
        let connection = try await FakeOTPConnection()
        connection.deviceInfoPages = [page(Data([4, 1, 3]))]
        connection.corruptsResponseCRC = true
        await #expect(throws: YubiOTP.SessionError.self) { try await connection.deviceName }
    }

    @Test("OTP HID reconstructs legacy metadata")
    func otpLegacy() async throws {
        let connection = try await FakeOTPConnection()
        connection.firmware = [2, 2, 0]
        let info = try await DeviceInfo.read(connection: connection, usbProductID: 0x0010)
        #expect(info.deviceName == "YubiKey")
        #expect(info.serialNumber == UInt(connection.serial))
        #expect(info.isApplicationSupported(.otp, over: .usb))
        #expect(!connection.dispatchedCommands.contains(0x13))
    }

    private func page(_ tlvs: Data) -> Data { Data([UInt8(tlvs.count)]) + tlvs }
}

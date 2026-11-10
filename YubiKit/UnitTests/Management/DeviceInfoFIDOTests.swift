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

struct DeviceInfoFIDOTests {
    @Test("FIDO HID reads Management information on modern keys")
    func management() async throws {
        let connection = NamingFIDOConnection(version: [5, 8, 0])
        let key = try await YubiKey(connection: connection)
        #expect(key.deviceName == "YubiKey 5C")
        #expect(key.deviceInfo.version == Version("5.8.0")!)
        #expect(await connection.commands == [0x86, 0xc2])
    }

    @Test(
        "FIDO HID identifies legacy families independently of CTAPHID version bytes",
        arguments: [
            (UInt16(0x0120), [UInt8(3), 0, 0], "FIDO U2F Security Key"),
            (UInt16(0x0113), [UInt8(1), 0, 2], "YubiKey NEO"),
            (UInt16(0x0116), [UInt8(4), 3, 7], "YubiKey NEO"),
            (UInt16(0x0410), [UInt8(1), 0, 2], "YubiKey Edge"),
        ]
    )
    func legacyVersion(pid: UInt16, version: [UInt8], expected: String) async throws {
        let connection = NamingFIDOConnection(version: version)
        let info = try await DeviceInfo.read(connection: connection, usbProductID: pid, usbVendorID: 0x1050)
        #expect(info.deviceName == expected)
        #expect(await connection.commands == [0x86])
    }

    @Test("Legacy FIDO naming requires Yubico identity", arguments: [nil, UInt16(0x1234)] as [UInt16?])
    func unidentifiedVendor(vid: UInt16?) async throws {
        let connection = NamingFIDOConnection(version: [3, 0, 0])
        await #expect(throws: ManagementSessionError.self) {
            try await DeviceInfo.read(connection: connection, usbProductID: 0x0120, usbVendorID: vid)
        }
        #expect(await connection.commands == (vid == nil ? [0x86] : []))
    }

    @Test("FIDO transport failures are propagated")
    func connectionFailure() async throws {
        let connection = NamingFIDOConnection(version: [5, 8, 0], fail: true)
        do {
            _ = try await YubiKey(connection: connection)
            Issue.record("Connection failure was ignored")
        } catch ManagementSessionError.fidoConnectionError(.connectionLost, _) {
        }
    }
}

private actor NamingFIDOConnection: FIDOConnection {
    nonisolated let mtu = 64
    private let version: [UInt8]
    private let fail: Bool
    private var response = Data()
    private(set) var commands: [UInt8] = []

    init(version: [UInt8], fail: Bool = false) {
        self.version = version
        self.fail = fail
    }

    init() async throws(FIDOConnectionError) { fatalError("Use the test initializer") }
    static func makeConnection() async throws(FIDOConnectionError) -> NamingFIDOConnection {
        fatalError("Use the test initializer")
    }

    func send(_ packet: Data) async throws(FIDOConnectionError) {
        if fail { throw .connectionLost }
        let command = packet[4]
        commands.append(command)
        let payload: Data
        switch command {
        case 0x86:
            payload = packet.subdata(in: 7..<15) + Data([0, 0, 0, 1, 2] + version + [0])
        case 0xc2:
            payload = Data([3, 4, 1, 3])  // Length-prefixed USB-C form factor TLV.
        default:
            preconditionFailure("Unexpected HID command")
        }
        response = packet.prefix(4) + Data([command, 0, UInt8(payload.count)]) + payload
        response.append(Data(count: mtu - response.count))
    }

    func receive() async throws(FIDOConnectionError) -> Data { response }
    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }
}

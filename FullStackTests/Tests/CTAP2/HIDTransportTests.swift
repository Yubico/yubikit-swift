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

#if os(macOS)

@Suite("CTAPHID Full Stack Tests", .serialized)
struct CTAPHIDFullStackTests {

    @Test("CTAPHID Interface Initialization")
    func interfaceInitialization() async throws {
        // First test HID connection enumeration
        let devices = try await HIDFIDOConnection.availableDevices()
        print("Found \(devices.count) FIDO HID devices")
        guard !devices.isEmpty else {
            print("No FIDO HID devices found, skipping test")
            return
        }

        // Test basic connection
        let connection = try await HIDFIDOConnection.makeConnection()
        print("Successfully opened HID connection")
        print("Connection MTU: \(connection.mtu)")

        // Test CTAPHID interface initialization
        let fidoInterface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)

        print("Successfully established CTAPHID connection")
        print("FIDO Interface Version: \(await fidoInterface.version)")
        print("FIDO Interface Capabilities: 0x\(String(format: "%02x", await fidoInterface.capabilities.rawValue))")

        #expect(await fidoInterface.version.description.isEmpty == false)
        #expect(await fidoInterface.capabilities != [])

        await connection.close(error: nil)
    }

    @Test("CTAPHID Capability Detection")
    func capabilityDetection() async throws {
        let connection = try await HIDFIDOConnection.makeConnection()
        let fidoInterface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)

        let supportsWink = await fidoInterface.supports(CTAP2.Capabilities.wink)
        let supportsCBOR = await fidoInterface.supports(CTAP2.Capabilities.cbor)
        let supportsNMSG = await fidoInterface.supports(CTAP2.Capabilities.nmsg)

        print("WINK capability: \(supportsWink)")
        print("CBOR capability: \(supportsCBOR)")
        print("NMSG capability: \(supportsNMSG)")

        #expect(supportsWink, "YubiKey should support WINK")

        await connection.close(error: nil)
    }

    @Test("CTAPHID WINK Command")
    func winkFunctionality() async throws {
        let connection = try await HIDFIDOConnection.makeConnection()
        let fidoInterface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)

        guard await fidoInterface.supports(CTAP2.Capabilities.wink) else {
            print("YubiKey does not support WINK, skipping test")
            await connection.close(error: nil)
            Issue.record("WINK not supported")
            return
        }

        print("Testing WINK functionality...")
        try await fidoInterface.wink()
        print("WINK command completed successfully!")

        #expect(true)

        await connection.close(error: nil)
    }

    @Test("CTAPHID PING Command")
    func pingCommand() async throws {
        let connection = try await HIDFIDOConnection.makeConnection()
        let fidoInterface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)

        print("Testing basic send/receive with PING command...")

        // Test empty ping
        let response1 = try await fidoInterface.ping()
        print("Empty PING response received: \(response1.hexEncodedString)")
        #expect(response1.bytes == [])

        // Test ping with data
        let pingData = Data([0x01, 0x02, 0x03, 0x04])
        let response2 = try await fidoInterface.ping(data: pingData)
        print("PING with data response received: \(response2.hexEncodedString)")
        #expect(response2 == pingData, "PING should echo back the same data")

        await connection.close(error: nil)
    }

    @Test("CTAPHID Error Handling")
    func errorHandling() async throws {
        let connection = try await HIDFIDOConnection.makeConnection()
        let fidoInterface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)

        print("Testing CTAPHID error handling...")

        do {
            // Send an invalid command
            let emptyPayload: Data? = nil
            _ = try await fidoInterface.sendAndReceive(cmd: 0xFF, payload: emptyPayload)  // Invalid command
            Issue.record("Invalid command should have failed")
        } catch let error {
            print("Invalid command correctly failed with CTAPHID error: \(error)")
            if case .hidError(let hidError, _) = error {
                print("HID error details: \(hidError)")
            }
        }

        await connection.close(error: nil)
    }
}

#endif

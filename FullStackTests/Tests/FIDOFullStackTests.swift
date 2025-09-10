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

#if os(macOS)

@Suite("FIDO Interface Full Stack Tests", .serialized)
struct FIDOInterfaceFullStackTests {

    @Test("FIDO Interface Initialization")
    func interfaceInitialization() async throws {
        // First test HID connection enumeration
        let devices = try await HIDFIDOConnection.availableDevices
        print("Found \(devices.count) FIDO HID devices")
        guard !devices.isEmpty else {
            print("No FIDO HID devices found, skipping test")
            return
        }

        // Test basic connection
        let connection = try await HIDFIDOConnection.connection()
        print("Successfully opened HID connection")
        print("Connection MTU: \(connection.mtu)")

        // Test FIDO interface initialization
        let fidoInterface = try await FIDOInterface(connection: connection)

        print("Successfully established FIDO connection")
        print("FIDO Interface Version: \(await fidoInterface.version)")
        print("FIDO Interface Capabilities: 0x\(String(format: "%02x", await fidoInterface.capabilities))")

        #expect(await fidoInterface.version.description.isEmpty == false)
        #expect(await fidoInterface.capabilities > 0)

        await connection.close(error: nil)
    }

    @Test("FIDO Capability Detection")
    func capabilityDetection() async throws {
        let connection = try await HIDFIDOConnection.connection()
        let fidoInterface = try await FIDOInterface(connection: connection)

        let supportsWink = await fidoInterface.supports(FIDOInterface.Capability.WINK)
        let supportsCBOR = await fidoInterface.supports(FIDOInterface.Capability.CBOR)
        let supportsNMSG = await fidoInterface.supports(FIDOInterface.Capability.NMSG)

        print("WINK capability: \(supportsWink)")
        print("CBOR capability: \(supportsCBOR)")
        print("NMSG capability: \(supportsNMSG)")

        // Most YubiKeys should support at least CBOR
        #expect(supportsCBOR, "YubiKey should support CBOR capability")

        await connection.close(error: nil)
    }

    @Test("FIDO WINK Functionality")
    func winkFunctionality() async throws {
        let connection = try await HIDFIDOConnection.connection()
        let fidoInterface = try await FIDOInterface(connection: connection)

        guard await fidoInterface.supports(FIDOInterface.Capability.WINK) else {
            print("YubiKey does not support WINK, skipping test")
            await connection.close(error: nil)
            return
        }

        print("Testing WINK functionality...")
        try await fidoInterface.wink()
        print("WINK command completed successfully!")

        #expect(true)

        await connection.close(error: nil)
    }

    @Test("FIDO PING Command")
    func pingCommand() async throws {
        let connection = try await HIDFIDOConnection.connection()
        let fidoInterface = try await FIDOInterface(connection: connection)

        print("Testing basic send/receive with PING command...")

        let pingData = Data([0x01, 0x02, 0x03, 0x04])
        let response = try await fidoInterface.sendAndReceive(cmd: 0x81, payload: pingData)  // PING command

        print("PING response received: \(response.hexEncodedString)")
        #expect(response == pingData, "PING should echo back the same data")

        await connection.close(error: nil)
    }

    @Test("FIDO Error Handling")
    func errorHandling() async throws {
        let connection = try await HIDFIDOConnection.connection()
        let fidoInterface = try await FIDOInterface(connection: connection)

        print("Testing FIDO error handling...")

        do {
            // Send an invalid command
            _ = try await fidoInterface.sendAndReceive(cmd: 0xFF, payload: nil)  // Invalid command
            Issue.record("Invalid command should have failed")
        } catch let error as CTAP.HIDError {
            print("Invalid command correctly failed with HID error: \(error)")
            #expect(true)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        await connection.close(error: nil)
    }
}

#endif

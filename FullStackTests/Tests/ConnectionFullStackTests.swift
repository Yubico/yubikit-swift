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

import CryptoTokenKit
import Testing

@testable import FullStackTests
@testable import YubiKit

@Suite("Connection Full Stack Tests", .serialized)
struct ConnectionFullStackTests {

    typealias Connection = USBSmartCardConnection

    @Test("Single Connection", .timeLimit(.minutes(1)))
    func singleConnection() async throws {
        let connection = try await Connection.connection()
        #expect(true, "✅ Got connection \(connection)")
        await connection.close(error: nil)
    }

    @Test("Serial Connections", .timeLimit(.minutes(1)))
    func serialConnections() async throws {
        let firstConnection = try await Connection.connection()
        #expect(true, "✅ Got first connection \(firstConnection)")
        let task = Task {
            let result = await firstConnection.connectionDidClose()
            #expect(true, "✅ First connection did close")
            return result
        }

        // attempt to create a second connection (should fail!)
        try? await Task.sleep(for: .seconds(1))
        let new = try? await Connection.connection()
        #expect(new == nil, "✅ Second connection failed as expected")

        // close the first connection
        _ = await firstConnection.close(error: nil)
        let closingError = await task.value
        #expect(closingError == nil, "✅ connectionDidClose() returned: \(String(describing: closingError))")

        // attempt to create a second connection (now it should succed!)
        try? await Task.sleep(for: .seconds(1))
        let secondConnection = try await Connection.connection()
        #expect(true, "✅ Got second connection \(secondConnection)")

        // close the second connection
        await secondConnection.close(error: nil)
    }

    @Test("Connection Cancellation", .timeLimit(.minutes(1)))
    func connectionCancellation() async {
        let task1 = Task {
            try await Connection.connection()
        }
        let task2 = Task {
            try await Connection.connection()
        }
        let task3 = Task {
            try await Connection.connection()
        }
        let task4 = Task {
            try await Connection.connection()
        }

        let result1 = try? await task1.value
        print("✅ Result 1: \(String(describing: result1))")
        let result2 = try? await task2.value
        print("✅ Result 2: \(String(describing: result2))")
        let result3 = try? await task3.value
        print("✅ Result 3: \(String(describing: result3))")
        let result4 = try? await task4.value
        print("✅ Result 4: \(String(describing: result4))")

        let connections = [result1, result2, result3, result4].compactMap { $0 }
        #expect(connections.count == 1)

        // close the only established connection
        await connections.first?.close(error: nil)
    }

    @Test("Send Manually", .timeLimit(.minutes(1)))
    func sendManually() async throws {
        let connection = try await Connection.connection()
        // Select Management application
        let apdu = APDU(
            cla: 0x00,
            ins: 0xa4,
            p1: 0x04,
            p2: 0x00,
            command: Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17])
        )
        let resultData = try await connection.send(data: apdu.data)
        let result = Response(rawData: resultData)
        #expect(result.responseStatus.status == .ok)
        /// Get version number
        let deviceInfoApdu = APDU(cla: 0, ins: 0x1d, p1: 0, p2: 0)
        let deviceInfoResultData = try await connection.send(data: deviceInfoApdu.data)
        let deviceInfoResult = Response(rawData: deviceInfoResultData)
        #expect(deviceInfoResult.responseStatus.status == .ok)
        let records = TKBERTLVRecord.sequenceOfRecords(
            from: deviceInfoResult.data.subdata(in: 1..<deviceInfoResult.data.count)
        )
        let versionData = try #require(
            records?.filter({ $0.tag == 0x05 }).first?.value,
            "No YubiKey version record in result."
        )
        #expect(versionData.count == 3, "Wrong sized return data. Got \(versionData.hexEncodedString)")
        let bytes = [UInt8](versionData)
        let major = bytes[0]
        let minor = bytes[1]
        let micro = bytes[2]
        print("✅ Got version: \(major).\(minor).\(micro)")
        #expect(major == 5)
        // Try to select non existing application
        let notFoundApdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00, command: Data([0x01, 0x02, 0x03]))
        let notFoundResultData = try await connection.send(data: notFoundApdu.data)
        let notFoundResult = Response(rawData: notFoundResultData)
        #expect(
            notFoundResult.responseStatus.status == .fileNotFound
                || notFoundResult.responseStatus.status == .incorrectParameters
                || notFoundResult.responseStatus.status == .invalidInstruction,
            "Unexpected result: \(notFoundResult.responseStatus)"
        )

        await connection.close(error: nil)
    }
}

#if os(iOS)
@Suite("NFC Full Stack Tests", .serialized)
struct NFCFullStackTests {

    @Test("NFC Alert Message", .timeLimit(.minutes(1)))
    func nfcAlertMessage() async throws {
        let connection = try await TestableConnections.create(with: .nfc(alertMessage: "Test Alert Message"))
        await connection.nfcConnection?.setAlertMessage("Updated Alert Message")
        try? await Task.sleep(for: .seconds(1))
        await connection.nfcConnection?.close(message: "Closing Alert Message")
    }

    @Test("NFC Closing Error Message", .timeLimit(.minutes(1)))
    func nfcClosingErrorMessage() async throws {
        let connection = try await TestableConnections.create(with: .nfc(alertMessage: "Test Alert Message"))
        await connection.close(error: nil)
    }

}
#endif

@Suite("SmartCard Connection Full Stack Tests", .serialized)
struct SmartCardConnectionFullStackTests {

    @Test("SmartCard Connection With Slot", .timeLimit(.minutes(1)))
    func smartCardConnectionWithSlot() async throws {
        let allSlots = try await USBSmartCardConnection.availableSlots
        allSlots.enumerated().forEach { index, slot in
            print("\(index): \(slot.name)")
        }
        let random = allSlots.randomElement()
        // we need at least one YubiKey connected
        let slot = try #require(random, "No YubiKey slots available")
        let connection = try await USBSmartCardConnection.connection(slot: slot)
        #expect(true, "✅ Got connection \(connection)")
    }

}

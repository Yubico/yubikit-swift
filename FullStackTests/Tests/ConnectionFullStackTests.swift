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

import XCTest
import CryptoTokenKit

@testable import YubiKit
@testable import FullStackTests

class ConnectionFullStackTests: XCTestCase {

    // Change Connection to test different types of connections
    typealias Connection = SmartCardConnection
    
    #if os(iOS)
    func testNFCAlertMessage() throws {
        runAsyncTest {
            do {
                let connection = try await NFCConnection.connection(alertMessage: "Test Alert Message")
                guard try await connection.isAllowed() else { XCTFail("🚨 YubiKey not in allow-list!"); return }
                connection.nfcConnection?.setAlertMessage("Updated Alert Message")
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                await connection.nfcConnection?.close(message: "Closing Alert Message")
            } catch {
                XCTFail("🚨 Failed with: \(error)")
            }
        }
    }
    
    func testNFCClosingErrorMessage() throws {
        runAsyncTest {
            do {
                let connection = try await NFCConnection.connection(alertMessage: "Test Alert Message")
                guard try await connection.isAllowed() else { XCTFail("🚨 YubiKey not in allow-list!"); return }
                await connection.close(error: "Closing Error Message")
            } catch {
                XCTFail("🚨 Failed with: \(error)")
            }
        }
    }
    
    #endif

    func testSmartCardConnectionWithSlot() throws {
        runAsyncTest {
            let allSlots = try await SmartCardConnection.availableSlots
            allSlots.enumerated().forEach { index, slot in
                print("\(index): \(slot.name)")
            }
            let random = allSlots.randomElement()
            XCTAssertNotNil(random) // we need at least one YubiKey connected
            let connection = try await SmartCardConnection.connection(slot: random!)
            print("✅ Got connection \(connection)")
            XCTAssertNotNil(connection)
        }
    }

    func testSingleConnection() throws {
        runAsyncTest() {
            do {
                let connection = try await Connection.connection()
                print("✅ Got connection \(connection)")
                XCTAssertNotNil(connection)
            } catch {
                XCTFail("🚨 Failed with: \(error)")
            }
        }
    }
    
    func testSerialConnections() throws {
        runAsyncTest() {
            do {
                let firstConnection = try await Connection.connection()
                guard try await firstConnection.isAllowed() else { XCTFail("🚨 YubiKey not in allow-list!"); return }
                print("✅ Got first connection \(firstConnection)")
                let task = Task {
                    let result = await firstConnection.connectionDidClose()
                    print("✅ First connection did close")
                    return result
                }
                try? await Task.sleep(nanoseconds: 1_000_000)
                let secondConnection = try await Connection.connection()
                print("✅ Got second connection \(secondConnection)")
                XCTAssertNotNil(secondConnection)
                let closingError = await task.value
                XCTAssertNil(closingError)
                print("✅ connectionDidClose() returned: \(String(describing: closingError))")
            } catch {
                XCTFail("🚨 Failed with: \(error)")
            }
        }
    }
    
    func testConnectionCancellation() {
        runAsyncTest {
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
            
            XCTAssert([result1, result2, result3, result4].compactMap { $0 }.count == 1)
        }
    }
    
    func testSendManually() {
        runAsyncTest {
            let connection = try await Connection.connection()
            // Select Management application
            let apdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00, command: Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]))
            let resultData = try await connection.send(data: apdu.data)
            let result = Response(rawData: resultData)
            XCTAssertEqual(result.responseStatus.status, .ok)
            /// Get version number
            let deviceInfoApdu = APDU(cla: 0, ins: 0x1d, p1: 0, p2: 0)
            let deviceInfoResultData = try await connection.send(data: deviceInfoApdu.data)
            let deviceInfoResult = Response(rawData: deviceInfoResultData)
            XCTAssertEqual(deviceInfoResult.responseStatus.status, .ok)
            let records = TKBERTLVRecord.sequenceOfRecords(from: deviceInfoResult.data.subdata(in: 1..<deviceInfoResult.data.count))
            guard let versionData = records?.filter({ $0.tag == 0x05 }).first?.value else { XCTFail("No YubiKey version record in result."); return }
            guard versionData.count == 3 else { XCTFail("Wrong sized return data. Got \(versionData.hexEncodedString)"); return }
            let bytes = [UInt8](versionData)
            let major = bytes[0]
            let minor = bytes[1]
            let micro = bytes[2]
            print("✅ Got version: \(major).\(minor).\(micro)")
            XCTAssertEqual(major, 5)
            // Try to select non existing application
            let notFoundApdu =  APDU(cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00, command: Data([0x01, 0x02, 0x03]))
            let notFoundResultData = try await connection.send(data: notFoundApdu.data)
            let notFoundResult = Response(rawData: notFoundResultData)
            if !(notFoundResult.responseStatus.status == .fileNotFound || notFoundResult.responseStatus.status == .incorrectParameters || notFoundResult.responseStatus.status == .invalidInstruction) {
                XCTFail("Unexpected result: \(notFoundResult.responseStatus)")
            }
        }
    }
}

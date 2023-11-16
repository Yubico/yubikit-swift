//
//  ConnectionFullStackTests.swift
//  FullStackTests
//
//  Created by Jens Utbult on 2023-09-08.
//

import XCTest
import YubiKit

@testable import FullStackTests

class ConnectionFullStackTests: XCTestCase {

    // Change Connection to test different types of connections
    typealias Connection = SmartCardConnection
    
    #if os(iOS)
    func testAlertMessage() throws {
        runAsyncTest {
            do {
                let connection = try await NFCConnection.connection(alertMessage: "Test Alert Message")
                connection.nfcConnection?.setAlertMessage("Updated Alert Message")
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                await connection.nfcConnection?.close(message: "Closing Alert Message")
            } catch {
                XCTFail("🚨 Failed with: \(error)")
            }
        }
    }
    
    func testClosingErrorMessage() throws {
        runAsyncTest {
            do {
                let connection = try await NFCConnection.connection(alertMessage: "Test Alert Message")
                await connection.close(error: "Closing Error Message")
            } catch {
                XCTFail("🚨 Failed with: \(error)")
            }
        }
    }
    
    #endif
    
    func testSingleConnection() throws {
        runAsyncTest() {
            do {
                let connection = try await ConnectionHelper.anyConnection()
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
                print("✅ connectionDidClose() returned: \(closingError ?? "nil")")
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
}

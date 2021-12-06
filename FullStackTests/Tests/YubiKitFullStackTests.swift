//
//  YubiKitFullStackTestsTests.swift
//  YubiKitFullStackTestsTests
//
//  Created by Jens Utbult on 2021-11-11.
//

import XCTest
import YubiKit

@testable import FullStackTests

class YubiKitFullStackTests: XCTestCase {

    func testCalculateCodes() throws {
        runAsyncTest {
            let connection = try await NFCConnection.connection()
            let session = try await OATHSession.session(withConnection: connection)
            let codes = try await session.calculateCodes()
            XCTAssert(codes.count == 6)
        }
    }
    
    func testQueuedCommands() throws {
        runAsyncTest {
            let connection = try await NFCConnection.connection()
            let session = try await OATHSession.session(withConnection: connection)
            let taskOne = Task.detached(priority: .low) {
                try await session.calculateCodes()
            }
            let taskTwo = Task.detached(priority: .background) {
                try await session.calculateCodes()
            }
            let taskThree = Task.detached(priority: .utility) {
                try await session.calculateCodes()
            }
            let all = try await [taskOne.value, taskTwo.value, taskThree.value]
            print("done")
        }
    }
    
    func testAlwaysFail() throws {
        runAsyncTest {
            let connection = try await NFCConnection.connection()
            let session = try await OATHSession.session(withConnection: connection)
            let code = try await session.calculateFailingCode()
            XCTAssert(code.count == 1)
        }
    }
}

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

    
    func testListAccounts() throws {
        runAsyncTest {
            let connection = try await NFCConnection.connection()
            let session = try await OATHSession.session(withConnection: connection)
            let accounts = try await session.listAccounts()
            accounts.forEach {
                print("🦠 \($0)")
            }
            XCTAssert(accounts.count == 4)
        }
    }
    
    func testListAccountsAndCalculate() throws {
        runAsyncTest {
            let connection = try await NFCConnection.connection()
            let session = try await OATHSession.session(withConnection: connection)
            let accounts = try await session.listAccounts()
            let codes = try await accounts.asyncMap { account in
                let code = try await session.calculateCode(account: account)
                print("🦠 \(account), \(code)")
                return code
            }
            XCTAssert(accounts.count == 4)
        }
    }
    
    func testCalculateCodes() throws {
        runAsyncTest {
            let connection = try await NFCConnection.connection()
            let session = try await OATHSession.session(withConnection: connection)
            let codes = try await session.calculateCodes()
            print("🦠 \(codes)")
            XCTAssert(codes.count == 4)
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
}

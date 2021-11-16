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

    func testExample() throws {
        runAsyncTest {
            print("Test started...")
            let connection = try await Connection.connection()
            print("Got connection")
            let session = try await connection.session()
            print("Got session")
            let code = try await session.calculateCode()
            print("Done!")
            XCTAssert(code.count == 1)
        }
    }
    
    func testError() throws {
        runAsyncTest {
            print("Test started...")
            let connection = try await Connection.connection()
            print("Got connection")
            let session = try await connection.session()
            print("Got session")
            let code = try await session.calculateFailingCode()
            print("Done!")
            XCTAssert(code.count == 1)
        }
    }

}

//
//  ManagementFullStackTests.swift
//  FullStackTestsTests
//
//  Created by Jens Utbult on 2023-01-12.
//

import XCTest
import YubiKit

@testable import FullStackTests

class ManagementFullStackTests: XCTestCase {
    
    func testReadKeyVersion() throws {
        runManagementTest { session in
            print("Got version: \(session.version)")
        }
    }
}

extension XCTestCase {
    func runManagementTest(named testName: String = #function,
                           in file: StaticString = #file,
                           at line: UInt = #line,
                           withTimeout timeout: TimeInterval = 20,
                           test: @escaping (ManagementSession) async throws -> Void) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await ConnectionHelper.anyConnection()
            let session = try await ManagementSession.session(withConnection: connection)
            try await test(session)
        }
    }
}

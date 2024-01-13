//
//  PIVFullStackTests.swift
//  FullStackTestsTests
//
//  Created by Jens Utbult on 2024-01-12.
//

import XCTest
import YubiKit

@testable import FullStackTests

final class PIVFullStackTests: XCTestCase {

    func testGetSession() throws {
        runPIVTest { session in
            print(session)
        }
    }
}

extension XCTestCase {
    func runPIVTest(named testName: String = #function,
                     in file: StaticString = #file,
                     at line: UInt = #line,
                     withTimeout timeout: TimeInterval = 20,
                     test: @escaping (PIVSession) async throws -> Void) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await AllowedConnections.anyConnection()
            var session = try await PIVSession.session(withConnection: connection)
//            try await session.reset()
            

            
            try await test(session)
        }
    }
}

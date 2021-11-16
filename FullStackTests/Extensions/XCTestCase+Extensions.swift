//
//  XCTestCase+Extensions.swift
//  FullStackTests
//
//  Created by Jens Utbult on 2021-11-16.
//

import XCTest

extension XCTestCase {
    
    // https://www.swiftbysundell.com/articles/unit-testing-code-that-uses-async-await/
    func runAsyncTest(named testName: String = #function,
                      in file: StaticString = #file,
                      at line: UInt = #line,
                      withTimeout timeout: TimeInterval = 10,
                      test: @escaping () async throws -> Void) {
        var thrownError: Error?
        let errorHandler = { thrownError = $0 }
        let expectation = expectation(description: testName)
        
        Task {
            do {
                try await test()
            } catch {
                errorHandler(error)
            }
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: timeout)
        
        if let error = thrownError {
            XCTFail("Async error thrown: \(error)", file: file, line: line)
        }
    }
}

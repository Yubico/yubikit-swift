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
import YubiKit

@testable import OATHSampleModel

@MainActor
final class ModelTests: XCTestCase {
    func testUsesOATHVersionWithoutSelectingManagement() async {
        let connection = TestConnection(suspendCalculation: false)
        let model = Model()
        let succeeded = await model.update(using: connection)

        XCTAssertTrue(succeeded)
        XCTAssertEqual(model.keyVersion, "5.7.1")
        XCTAssertNil(model.error)
        let selections = await connection.selections
        XCTAssertEqual(selections, 1)
    }

    func testCancelledUpdateDiscardsLateResult() async throws {
        let connection = TestConnection(suspendCalculation: true)
        let model = Model()
        let update = Task { await model.update(using: connection) }
        defer { update.cancel() }
        try await connection.waitForCalculation()

        update.cancel()
        await connection.finishCalculation()
        let succeeded = await update.value

        XCTAssertFalse(succeeded)
        XCTAssertNil(model.keyVersion)
        XCTAssertNil(model.connectionType)
        XCTAssertTrue(model.accounts.isEmpty)
    }

    func testCancellationClosesWiredConnectionAndClearsDisplay() async throws {
        let connection = TestConnection(suspendCalculation: false)
        let model = Model()
        let monitor = Task { await model.monitorWiredConnections { connection } }
        defer { monitor.cancel() }
        try await connection.waitForCloseWaiter()
        XCTAssertEqual(model.keyVersion, "5.7.1")

        monitor.cancel()
        await monitor.value

        let closed = await connection.closed
        XCTAssertTrue(closed)
        XCTAssertNil(model.keyVersion)
        XCTAssertNil(model.connectionType)
    }

    func testFailedRefreshClearsPreviousResult() async {
        let model = Model()
        await model.update(using: TestConnection(suspendCalculation: false))
        XCTAssertEqual(model.accounts.count, 1)
        XCTAssertNotNil(model.accounts.first?.code)
        let succeeded = await model.update(using: TestConnection(failCalculation: true))

        XCTAssertFalse(succeeded)
        XCTAssertNil(model.keyVersion)
        XCTAssertNil(model.connectionType)
        XCTAssertTrue(model.accounts.isEmpty)
        XCTAssertNotNil(model.error)
        XCTAssertNotNil(model.readError)
        model.error = nil
        XCTAssertNotNil(model.readError)
    }
}

private actor TestConnection: SmartCardConnection {
    private let suspendCalculation: Bool
    private let failCalculation: Bool
    private var calculationStarted = false
    private var calculation: CheckedContinuation<Void, Never>?
    private var closeWaiter: CheckedContinuation<Error?, Never>?
    private(set) var closed = false
    private(set) var selections = 0

    init(suspendCalculation: Bool = false, failCalculation: Bool = false) {
        self.suspendCalculation = suspendCalculation
        self.failCalculation = failCalculation
    }

    init() async throws(SmartCardConnectionError) {
        suspendCalculation = false
        failCalculation = false
    }

    static func makeConnection() async throws(SmartCardConnectionError) -> TestConnection {
        TestConnection(suspendCalculation: false)
    }

    func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        if data[1] == 0xa4, data[2] == 0x04 {
            selections += 1
            guard selections == 1 else { throw .unsupported }
            // OATH SELECT: version 5.7.1 and an eight-byte device salt.
            return Data([0x79, 3, 5, 7, 1, 0x71, 8] + Array("salt1234".utf8) + [0x90, 0])
        }
        if data[1] == 0xa2 {
            return Data([0x76, 5, 6, 0, 1, 0xe2, 0x40, 0x90, 0])
        }
        guard data[1] == 0xa4 else { throw .unsupported }
        calculationStarted = true
        if suspendCalculation {
            await withCheckedContinuation { calculation = $0 }
        }
        if failCalculation { throw .connectionLost }
        // One six-digit TOTP result for the synthetic account "test".
        return Data([0x71, 4] + Array("test".utf8) + [0x76, 5, 6, 0, 1, 0xe2, 0x40, 0x90, 0])
    }

    func close(error: Error?) async {
        closed = true
        closeWaiter?.resume(returning: error)
        closeWaiter = nil
    }

    func waitUntilClosed() async -> Error? {
        if closed { return nil }
        return await withCheckedContinuation { closeWaiter = $0 }
    }

    func waitForCalculation() async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !calculationStarted {
            guard ContinuousClock.now < deadline else { throw TestError.timeout }
            try await Task.sleep(for: .milliseconds(1))
        }
    }

    func finishCalculation() {
        calculation?.resume()
        calculation = nil
    }

    func waitForCloseWaiter() async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while closeWaiter == nil {
            guard ContinuousClock.now < deadline else { throw TestError.timeout }
            try await Task.sleep(for: .milliseconds(1))
        }
    }

    private enum TestError: Error {
        case timeout
    }
}

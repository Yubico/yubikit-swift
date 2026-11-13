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

import Foundation
import Testing

@testable import YubiKit

@Suite("Timeout cancellation", .timeLimit(.minutes(1)))
struct TaskTimeoutTests {

    @Test("caller cancellation returns the operation's result instead of a timeout")
    func callerCancellationKeepsResult() async throws {
        let started = Promise<Void>()
        let response = Promise<Int>()
        let task = Task {
            try await withTimeoutIgnoringCancellation(.seconds(30)) {
                await started.fulfill(())
                // Promise.value ignores cancellation, like a transport receive.
                return try await response.value()
            }
        }

        try await started.value()
        task.cancel()
        // Verify caller cancellation does not return before the operation responds.
        try await Task.sleep(for: .milliseconds(50))
        await response.fulfill(42)

        #expect(try await task.value == 42)
    }

    @Test("an operation that outlasts the deadline times out")
    func timesOut() async {
        let result = await withTimeoutIgnoringCancellation(.milliseconds(10)) { () async -> Int in
            try? await Task.sleep(for: .seconds(30))
            return 1
        }
        #expect(result == nil)
    }

    @Test("a blocked receive returns at the deadline")
    func blockedReceiveTimesOut() async throws {
        let response = Promise<Int>()
        let start = ContinuousClock.now
        let result = try await withTimeoutIgnoringCancellation(.milliseconds(20)) {
            try await withTaskCancellationHandler {
                try await response.value()
            } onCancel: {
                Task { await response.cancel(with: CancellationError()) }
            }
        }
        #expect(result == nil)
        #expect(start.duration(to: .now) < .seconds(1))
    }

    @Test("a finished operation does not wait for the deadline")
    func returnsWithoutWaitingForDeadline() async {
        let start = ContinuousClock.now
        let result = await withTimeoutIgnoringCancellation(.seconds(30)) { 1 }
        #expect(result == 1)
        #expect(start.duration(to: .now) < .seconds(5))
    }

    @Test("a caller cancelled before starting the timeout still runs the operation")
    func alreadyCancelledCallerKeepsOperation() async throws {
        let started = Promise<Void>()
        let resume = Promise<Void>()
        let task = Task {
            await started.fulfill(())
            try await resume.value()
            return await withTimeoutIgnoringCancellation(.seconds(30)) { 42 }
        }

        try await started.value()
        task.cancel()
        await resume.fulfill(())

        #expect(try await task.value == 42)
    }

    @Test("the timeout preserves the operation's typed error")
    func operationErrorIsPreserved() async {
        do {
            _ = try await withTimeoutIgnoringCancellation(.seconds(30)) {
                () async throws(TimeoutTestError) -> Int in
                throw .failed
            }
            Issue.record("Expected the operation to throw")
        } catch {
            #expect(error == .failed)
        }
    }
}

private enum TimeoutTestError: Error, Equatable {
    case failed
}

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

@_spi(YubiInternal) @testable import YubiKit

@Suite("WebAuthn status stream cancellation", .timeLimit(.minutes(1)))
struct WebAuthnStatusStreamCancellationTests {

    @Test("Value reports caller cancellation", arguments: [false, true])
    func testValueCancellation(timed: Bool) async {
        let stream = WebAuthn.StatusStream<String> { continuation in
            continuation.yield(.processing)
        }

        do {
            _ = try await withDeadline {
                withUnsafeCurrentTask { $0?.cancel() }
                return try await stream.withTimeout(timed ? .milliseconds(100) : nil).value
            }
            Issue.record("Expected cancellation")
        } catch {
            guard case WebAuthn.ClientError.cancelled = error else {
                Issue.record("Expected cancellation, got \(error)")
                return
            }
        }
    }

    @Test("Cancelling the consumer of a timed stream cancels its producer")
    func testCancellationReachesProducer() async throws {
        let producerCancelled = Promise<Bool>()
        let stream = WebAuthn.StatusStream<String> { continuation in
            let task = Task {
                continuation.yield(.processing)
                try? await Task.sleep(for: .seconds(60))
                await producerCancelled.fulfill(Task.isCancelled)
            }
            continuation.cancelOnTermination(task)
        }.withTimeout(.seconds(60))

        _ = await Task {
            for try await status in stream {
                if case .processing = status { withUnsafeCurrentTask { $0?.cancel() } }
            }
        }.result

        #expect(try await withDeadline { try await producerCancelled.value() } == true)
    }

    // Iterator cancellation lets the watchdog turn a stalled stream into a test failure.
    private func withDeadline<T: Sendable>(
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T? {
        try await withThrowingTaskGroup(of: T?.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(for: .seconds(5))
                return nil
            }
            defer { group.cancelAll() }
            return try await group.next() ?? nil
        }
    }

}

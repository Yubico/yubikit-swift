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

@Suite("WebAuthn StatusStream Tests")
struct StatusStreamTests {

    // MARK: - Value Property

    @Test("Value extracts finished response", arguments: [false, true])
    func testValueExtractsResponse(timed: Bool) async throws {
        let stream = WebAuthn.StatusStream<String> { continuation in
            continuation.yield(.processing)
            continuation.yield(.finished("success"))
        }

        let result = try await withDeadline {
            try await stream.withTimeout(timed ? .seconds(60) : nil).value
        }
        #expect(result == "success")
    }

    @Test("Value throws on error", arguments: [false, true])
    func testValueThrowsOnError(timed: Bool) async {
        let stream = WebAuthn.StatusStream<String> { continuation in
            continuation.yield(.processing)
            continuation.yield(error: .cancelled(source: .here()))
        }

        do {
            _ = try await withDeadline {
                try await stream.withTimeout(timed ? .seconds(60) : nil).value
            }
            Issue.record("Should have thrown")
        } catch let error {
            guard case WebAuthn.ClientError.cancelled = error else {
                Issue.record("Expected cancelled, got \(error)")
                return
            }
        }
    }

    // MARK: - Timeout

    @Test("Timeout fires when stream stalls")
    func testTimeoutFires() async {
        let stream = WebAuthn.StatusStream<String> { continuation in
            continuation.yield(.processing)
        }

        let timedStream = stream.withTimeout(.milliseconds(100))

        do {
            _ = try await withDeadline { try await timedStream.value }
            Issue.record("Should have timed out")
        } catch let error {
            guard case WebAuthn.ClientError.timeout = error else {
                Issue.record("Expected timeout, got \(error)")
                return
            }
        }
    }

    @Test("Completes before timeout")
    func testCompletesBeforeTimeout() async throws {
        let stream = WebAuthn.StatusStream<String> { continuation in
            continuation.yield(.processing)
            continuation.yield(.finished("fast"))
        }

        let timedStream = stream.withTimeout(.seconds(10))
        let result = try await withDeadline { try await timedStream.value }
        #expect(result == "fast")
    }

    @Test("Timeout forwards source completion", arguments: [false, true])
    func testTimeoutForwardsCompletion(closedBeforeWrapping: Bool) async throws {
        var sourceContinuation: WebAuthn.StatusStream<String>.Continuation?
        let source = WebAuthn.StatusStream<String> { continuation in
            sourceContinuation = continuation
            continuation.yield(.processing)
        }
        let continuation = try #require(sourceContinuation)
        if closedBeforeWrapping { continuation.finish() }
        let stream = source.withTimeout(.seconds(60))

        let ended = try await withDeadline {
            var iterator = stream.makeAsyncIterator()
            guard case .processing? = try await iterator.next() else {
                Issue.record("Expected processing status")
                return false
            }
            if !closedBeforeWrapping { continuation.finish() }
            return try await iterator.next() == nil
        }
        #expect(ended == true)
    }

    @Test("Value rejects source completion without a response", arguments: [false, true])
    func testValueRejectsMissingResponse(timed: Bool) async {
        let stream = WebAuthn.StatusStream<String> { continuation in
            continuation.yield(.processing)
            continuation.finish()
        }

        do {
            _ = try await withDeadline {
                try await stream.withTimeout(timed ? .seconds(60) : nil).value
            }
            Issue.record("Expected an internal error")
        } catch {
            guard case WebAuthn.ClientError.internalError = error else {
                Issue.record("Expected internal error, got \(error)")
                return
            }
        }
    }

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

    @Test("Timeout preserves the upstream error")
    func testTimeoutPreservesError() async {
        let stream = WebAuthn.StatusStream<String> { continuation in
            continuation.yield(.processing)
            continuation.yield(error: .invalidRequest("original error", source: .here()))
        }

        do {
            _ = try await withDeadline { try await stream.withTimeout(.seconds(60)).value }
            Issue.record("Expected the upstream error")
        } catch {
            guard case WebAuthn.ClientError.invalidRequest(let message, _) = error else {
                Issue.record("Expected invalid request, got \(error)")
                return
            }
            #expect(message == "original error")
        }
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

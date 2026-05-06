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

@Suite("WebAuthn StatusStream Tests")
struct StatusStreamTests {

    // MARK: - Value Property

    @Test("Value extracts finished response")
    func testValueExtractsResponse() async throws {
        let stream = WebAuthn.StatusStream<String> { continuation in
            continuation.yield(.processing)
            continuation.yield(.finished("success"))
        }

        let result = try await stream.value
        #expect(result == "success")
    }

    @Test("Value throws on error")
    func testValueThrowsOnError() async {
        let stream = WebAuthn.StatusStream<String> { continuation in
            continuation.yield(.processing)
            continuation.yield(error: .cancelled(source: .here()))
        }

        do {
            _ = try await stream.value
            Issue.record("Should have thrown")
        } catch let error {
            guard case .cancelled = error else {
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
            // Never yields .finished - simulates stall
            Task {
                try? await Task.sleep(for: .milliseconds(500))
                continuation.finish()
            }
        }

        let timedStream = stream.withTimeout(.milliseconds(100))

        do {
            _ = try await timedStream.value
            Issue.record("Should have timed out")
        } catch let error {
            guard case .timeout = error else {
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
        let result = try await timedStream.value
        #expect(result == "fast")
    }

}

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

@Suite("CTAP2 StatusStream Tests", .timeLimit(.minutes(1)))
struct CTAPStatusStreamTests {

    @Test("value throws keepaliveCancel when the awaiting task is cancelled")
    func valueReportsCancellation() async throws {
        let stream = CTAP2.StatusStream<String> { continuation in
            continuation.yield(.processing)
        }
        let task = Task { try await stream.value }

        // Let the task suspend on the stream so the cancel interrupts the wait.
        try await Task.sleep(for: .milliseconds(50))
        task.cancel()

        do {
            _ = try await task.value
            Issue.record("Expected cancellation")
        } catch CTAP2.SessionError.ctapError(.keepaliveCancel, _) {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}

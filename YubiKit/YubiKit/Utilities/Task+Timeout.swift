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

// Execute async operation with timeout. Returns nil if timeout occurs, result otherwise.
@inlinable
func withTimeout<T: Sendable, E: Error>(
    _ timeout: Duration,
    clock: ContinuousClock = ContinuousClock(),
    operation: @Sendable @escaping () async throws(E) -> T
) async throws(E) -> T? {
    do {
        return try await withThrowingTaskGroup(of: T?.self, returning: T?.self) { group in
            // 1) The real work
            group.addTask {
                let value = try await operation()
                return value
            }

            // 2) The timer (returns nil when it fires)
            group.addTask {
                try? await clock.sleep(for: timeout)
                return nil
            }

            // 3) Whichever completes first decides the result
            let first = try await group.next()!
            group.cancelAll()  // Cancel the loser
            return first
        }
    } catch {
        throw error as! E
    }
}

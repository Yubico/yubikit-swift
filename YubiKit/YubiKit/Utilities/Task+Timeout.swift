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

// Finish an exchange's wait even if its caller is cancelled. The timeout cancels the operation
// and returns nil after it exits, so the operation must cooperate with timeout cancellation.
@inlinable
func withTimeoutIgnoringCancellation<T: Sendable, E: Error>(
    _ timeout: Duration,
    clock: ContinuousClock = ContinuousClock(),
    operation: @Sendable @escaping () async throws(E) -> T
) async throws(E) -> T? {
    let race = Task {
        await withTaskGroup(of: Result<T?, E>.self) { group in
            group.addTask {
                do throws(E) {
                    return .success(try await operation())
                } catch {
                    return .failure(error)
                }
            }

            group.addTask {
                try? await clock.sleep(for: timeout)
                return .success(nil)
            }

            defer { group.cancelAll() }
            return await group.next()!
        }
    }
    return try await race.value.get()
}

// Sleeps for the full duration even if the caller is cancelled, so a poll loop that must finish
// its exchange does not spin.
func sleepIgnoringCancellation(for duration: Duration) async {
    await Task { try? await Task.sleep(for: duration) }.value
}

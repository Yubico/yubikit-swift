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

// Serializes async operations without holding a thread lock while they run.
final class AsyncMutex: @unchecked Sendable {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Bool, Never>
    }

    private let lock = NSLock()
    private var isLocked = false
    private var waiters: [Waiter] = []

    var queuedWaiterCount: Int { lock.withLock { waiters.count } }

    /// Returns false if the waiting task was cancelled.
    func acquire() async -> Bool {
        guard !Task.isCancelled else { return false }
        let id = UUID()
        let acquired = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let immediate = lock.withLock { () -> Bool? in
                    if Task.isCancelled { return false }
                    if !isLocked {
                        isLocked = true
                        return true
                    }
                    waiters.append(Waiter(id: id, continuation: continuation))
                    return nil
                }
                if let immediate { continuation.resume(returning: immediate) }
            }
        } onCancel: {
            cancelWaiter(id: id)
        }
        if acquired && Task.isCancelled {
            release()
            return false
        }
        return acquired
    }

    func release() {
        let next = lock.withLock { () -> CheckedContinuation<Bool, Never>? in
            precondition(isLocked)
            guard !waiters.isEmpty else {
                isLocked = false
                return nil
            }
            return waiters.removeFirst().continuation
        }
        next?.resume(returning: true)
    }

    private func cancelWaiter(id: UUID) {
        let cancelled = lock.withLock { () -> CheckedContinuation<Bool, Never>? in
            guard let index = waiters.firstIndex(where: { $0.id == id }) else { return nil }
            return waiters.remove(at: index).continuation
        }
        cancelled?.resume(returning: false)
    }
}

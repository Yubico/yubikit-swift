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

import Testing

@testable import YubiKit

struct AsyncMutexTests {
    @Test func handsOffToWaitingTask() async throws {
        let mutex = AsyncMutex()
        #expect(await mutex.acquire())
        let waiter = Task { await mutex.acquire() }
        try await waitForQueuedWaiter(in: mutex)
        mutex.release()
        #expect(await waiter.value)
        mutex.release()
        #expect(await mutex.acquire())
        mutex.release()
    }

    @Test func cancelledWaiterDoesNotTakeTheLock() async throws {
        let mutex = AsyncMutex()
        #expect(await mutex.acquire())
        let waiter = Task { await mutex.acquire() }
        try await waitForQueuedWaiter(in: mutex)
        waiter.cancel()
        #expect(await !waiter.value)
        mutex.release()
        #expect(await mutex.acquire())
        mutex.release()
    }

    private func waitForQueuedWaiter(in mutex: AsyncMutex) async throws {
        let deadline = ContinuousClock.now + .seconds(2)
        while mutex.queuedWaiterCount == 0 && ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(1))
        }
        try #require(mutex.queuedWaiterCount == 1)
    }
}

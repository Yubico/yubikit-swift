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

extension CFRunLoop {
    private func schedule(block: @Sendable @escaping () -> Void) {
        CFRunLoopPerformBlock(self, CFRunLoopMode.defaultMode.rawValue, block)
        CFRunLoopWakeUp(self)
    }

    func perform<T, E>(_ work: @Sendable @escaping () -> Result<T, E>) async throws(E) -> T {
        try await withCheckedContinuation { continuation in
            schedule {
                let retVal = work()
                continuation.resume(returning: retVal)
            }
        }.get()
    }

    func perform<T>(_ work: @Sendable @escaping () -> T) async -> T {
        await withCheckedContinuation { continuation in
            schedule {
                let retVal = work()
                continuation.resume(returning: retVal)
            }
        }
    }
}

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

actor CTAPOperationGate {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Bool, Never>
    }

    private var activeOperationID: UUID?
    private var waiters: [Waiter] = []

    func acquire(_ operationID: UUID) async -> Bool {
        guard !Task.isCancelled else { return false }

        if activeOperationID == nil {
            activeOperationID = operationID
        } else {
            let acquired = await withTaskCancellationHandler {
                await withCheckedContinuation { continuation in
                    if Task.isCancelled {
                        continuation.resume(returning: false)
                    } else {
                        waiters.append(Waiter(id: operationID, continuation: continuation))
                    }
                }
            } onCancel: {
                Task { await self.cancelWaiter(operationID) }
            }

            guard acquired else { return false }
        }

        guard !Task.isCancelled else {
            release(operationID)
            return false
        }
        return true
    }

    func release(_ operationID: UUID) {
        guard activeOperationID == operationID else { return }

        guard !waiters.isEmpty else {
            activeOperationID = nil
            return
        }

        let next = waiters.removeFirst()
        activeOperationID = next.id
        next.continuation.resume(returning: true)
    }

    private func cancelWaiter(_ operationID: UUID) {
        guard let index = waiters.firstIndex(where: { $0.id == operationID }) else { return }
        waiters.remove(at: index).continuation.resume(returning: false)
    }
}

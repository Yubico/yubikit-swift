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

/// Simple one‑time broadcast promise.
///
/// - call `value()` to suspend until someone calls `fulfill(_:)`
/// - call `fulfill(_:)` exactly once to resume everyone
final class Promise<Value: Sendable>: Sendable {
    private struct DisposedError: Error {}

    private let state = MutableState()

    private actor MutableState {
        var continuations: [CheckedContinuation<Value, Error>] = []
        var backingValue: Value?

        func value() async throws -> Value {
            if let value = backingValue {
                return value
            }
            return try await withCheckedThrowingContinuation { continuation in
                continuations.append(continuation)
            }
        }

        func fulfill(_ value: Value) {
            guard backingValue == nil else { return }
            backingValue = value
            continuations.forEach { $0.resume(returning: value) }
            continuations.removeAll()
        }

        func cancel() {
            guard backingValue == nil else { return }
            continuations.forEach { $0.resume(throwing: DisposedError()) }
            continuations.removeAll()
        }
    }

    /// Suspend until `fulfill(_:)` is called (or return immediately if already fulfilled).
    ///
    /// - Note: Upon deinitialization, any tasks awaiting 'value()' will resume with a 'DisposedError'.
    func value() async throws -> Value {
        try await state.value()
    }

    /// Resume all waiters with `value`, clear them, and stash the result.
    func fulfill(_ value: Value) async {
        await state.fulfill(value)
    }

    /// Cancels any pending waiters when the promise is deinitialized.
    ///
    /// - Note: Upon deinitialization, any tasks awaiting `value()` will resume with a `DisposedError`.
    deinit {
        Task { [state] in await state.cancel() }
    }
}

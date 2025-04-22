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
/// - get `value` to suspend until someone calls `fulfill(_:)`
/// - call `fulfill(_:)` exactly once to resume everyone
actor Promise<Value: Sendable> {
    private var continuations: [CheckedContinuation<Value, Never>] = []
    private var backingValue: Value? = nil

    /// Suspend until `fulfill(_:)` is called (or return immediately if already fulfilled).
    var value: Value {
        get async {
            if let value = backingValue {
                return value
            }
            return await withCheckedContinuation { continuation in
                continuations.append(continuation)
            }
        }
    }

    /// Resume all waiters with `value`, clear them, and stash the result.
    func fulfill(_ value: Value) {
        guard backingValue == nil else { return }
        backingValue = value
        continuations.forEach { $0.resume(returning: value) }
        continuations.removeAll()
    }
}

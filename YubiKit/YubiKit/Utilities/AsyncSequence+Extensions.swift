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

extension AsyncSequence where Self: Sendable, Element: Sendable & Equatable {
    /// Creates an async stream that omits repeated elements.
    func removeDuplicates() -> AsyncStream<Element> {
        removeDuplicates { $0 == $1 }
    }
}

extension AsyncSequence where Self: Sendable, Element: Sendable {
    /// Creates an async stream that omits repeated elements by testing with a predicate.
    func removeDuplicates(
        by predicate: @escaping @Sendable (Element, Element) async -> Bool
    ) -> AsyncStream<Element> {
        let source = self
        return AsyncStream { continuation in
            Task {
                var last: Element?
                do {
                    for try await element in source {
                        if let last = last, await predicate(last, element) {
                            continue
                        }
                        last = element
                        continuation.yield(element)
                    }
                } catch {
                    // Stream ends on error
                }
                continuation.finish()
            }
        }
    }
}

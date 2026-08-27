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

/// Protocol for status types that can signal completion.
protocol StreamStatus<Response>: Sendable {
    associatedtype Response: Sendable
    /// Returns the response if this is a terminal status, nil otherwise.
    var finishedResponse: Response? { get }
}

/// Async sequence that yields status updates with typed errors.
struct StatusStreamBase<Status: StreamStatus, Failure: Error & Sendable>: AsyncSequence,
    @unchecked Sendable
{
    typealias Element = Status

    private let stream: AsyncStream<Result<Status, Failure>>

    init(_ build: @escaping (Continuation) -> Void) {
        self.stream = AsyncStream { continuation in
            build(Continuation(continuation))
        }
    }

    func makeAsyncIterator() -> Iterator {
        Iterator(stream.makeAsyncIterator())
    }

    struct Iterator: AsyncIteratorProtocol {
        private var iterator: AsyncStream<Result<Status, Failure>>.AsyncIterator

        fileprivate init(_ iterator: AsyncStream<Result<Status, Failure>>.AsyncIterator) {
            self.iterator = iterator
        }

        mutating func next() async throws(Failure) -> Status? {
            guard let result = await iterator.next() else { return nil }
            return try result.get()
        }
    }
}

// MARK: - Helpers

extension StatusStreamBase {

    /// Create a stream that immediately yields an error.
    static func error(_ error: Failure) -> StatusStreamBase {
        StatusStreamBase { continuation in
            continuation.yield(error: error)
        }
    }

    /// Wraps this stream with a timeout that yields the given error.
    func timeout(_ duration: Duration, error timeoutError: Failure) -> StatusStreamBase {
        StatusStreamBase { continuation in
            Task {
                let completed = await withTaskGroup(of: Bool.self) { group in
                    group.addTask {
                        do {
                            for try await status in self {
                                continuation.yield(status)
                            }
                        } catch let error as Failure {
                            continuation.yield(error: error)
                        } catch {}
                        return true
                    }

                    group.addTask {
                        try? await Task.sleep(for: duration)
                        return false
                    }

                    let first = await group.next() ?? false
                    group.cancelAll()
                    return first
                }

                if !completed {
                    continuation.yield(error: timeoutError)
                }
            }
        }
    }

    struct Continuation: Sendable {
        private let continuation: AsyncStream<Result<Status, Failure>>.Continuation

        fileprivate init(_ continuation: AsyncStream<Result<Status, Failure>>.Continuation) {
            self.continuation = continuation
        }

        func yield(_ status: Status) {
            continuation.yield(.success(status))
            if status.finishedResponse != nil {
                continuation.finish()
            }
        }

        func yield(error: Failure) {
            continuation.yield(.failure(error))
            continuation.finish()
        }

        func finish() {
            continuation.finish()
        }
    }
}

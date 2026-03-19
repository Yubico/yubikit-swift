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

/// An async sequence that yields status updates and can throw typed errors.
///
/// - Note: Use the namespace-specific typealiases ``CTAP2/StatusStream`` and
///   ``WebAuthn/StatusStream`` instead of this type directly.
public struct StatusStreamBase<Response: Sendable, Failure: Error & Sendable>: AsyncSequence, @unchecked Sendable {
    public typealias Element = CTAP2.Status<Response>

    private let stream: AsyncStream<Result<CTAP2.Status<Response>, Failure>>

    init(_ build: @escaping (Continuation) -> Void) {
        let baseStream = AsyncStream { continuation in
            build(Continuation(continuation))
        }
        self.stream = baseStream.removeDuplicates { lhs, rhs in
            switch (lhs, rhs) {
            case (.success(.processing), .success(.processing)),
                (.success(.waitingForUser), .success(.waitingForUser)):
                true
            default:
                false
            }
        }
    }

    /// Consumes the stream and returns the final response value.
    ///
    /// This property iterates through all status updates and returns the response
    /// from the `.finished` case. Intermediate status updates are ignored.
    ///
    /// - Throws: The `Failure` error type if the operation fails.
    /// - Returns: The response value from the completed operation.
    public var value: Response {
        get async throws(Failure) {
            for try await status in self {
                if case .finished(let response) = status {
                    return response
                }
            }
            preconditionFailure("StatusStream must yield .finished before ending")
        }
    }

    public func makeAsyncIterator() -> Iterator {
        Iterator(stream.makeAsyncIterator())
    }

    public struct Iterator: AsyncIteratorProtocol {
        private var iterator: AsyncStream<Result<CTAP2.Status<Response>, Failure>>.AsyncIterator

        fileprivate init(_ iterator: AsyncStream<Result<CTAP2.Status<Response>, Failure>>.AsyncIterator) {
            self.iterator = iterator
        }

        public mutating func next() async throws(Failure) -> CTAP2.Status<Response>? {
            guard let result = await iterator.next() else { return nil }
            return try result.get()
        }
    }
}

// MARK: - Internal

extension StatusStreamBase {

    /// Create a stream that immediately yields an error.
    static func error(_ error: Failure) -> StatusStreamBase {
        StatusStreamBase { continuation in
            continuation.yield(error: error)
        }
    }

    /// Wraps this stream with an optional timeout.
    func withTimeout(_ duration: Duration?) -> StatusStreamBase where Failure == WebAuthn.ClientError {
        guard let duration else { return self }
        return timeout(duration, error: .timeout(source: .here()))
    }

    /// Wraps this stream with a timeout.
    private func timeout(_ duration: Duration, error timeoutError: Failure) -> StatusStreamBase {
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
        private let continuation: AsyncStream<Result<CTAP2.Status<Response>, Failure>>.Continuation

        fileprivate init(_ continuation: AsyncStream<Result<CTAP2.Status<Response>, Failure>>.Continuation) {
            self.continuation = continuation
        }

        func yield(_ status: CTAP2.Status<Response>) {
            continuation.yield(.success(status))
            if case .finished = status {
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

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

extension CTAP {
    /// An async sequence that yields status updates and can throw typed errors.
    ///
    /// This sequence streams ``CTAP/Status`` updates during long-running CTAP operations,
    /// and can throw ``CTAP.SessionError``.
    ///
    /// ## Usage
    ///
    /// For simple cases where you don't need status updates, use the ``value`` property:
    ///
    /// ```swift
    /// let credential = try await session.makeCredential(parameters: params).value
    /// ```
    ///
    /// For UI or when you need to react to status updates, iterate the stream:
    ///
    /// ```swift
    /// for try await status in await session.makeCredential(parameters: params) {
    ///     switch status {
    ///     case .processing:
    ///         print("Processing...")
    ///     case .waitingForUser:
    ///         showMessage("Touch your YubiKey")
    ///     case .finished(let response):
    ///         return response
    ///     }
    /// }
    /// ```
    struct StatusStream<Response: Sendable>: AsyncSequence {
        typealias Element = CTAP.Status<Response>

        private let stream: AsyncStream<Result<CTAP.Status<Response>, CTAP.SessionError>>

        init(_ build: @escaping (Continuation) -> Void) {
            self.stream = AsyncStream { continuation in
                build(Continuation(continuation))
            }
        }

        /// Consumes the stream and returns the final response value.
        ///
        /// This property iterates through all status updates and returns the response
        /// from the `.finished` case. Intermediate status updates (`.processing`,
        /// `.waitingForUser`) are ignored.
        ///
        /// Use this when you don't need to react to status updates and just want the result.
        ///
        /// - Throws: ``CTAP.SessionError`` if the operation fails.
        /// - Returns: The response value from the completed operation.
        public var value: Response {
            get async throws(CTAP.SessionError) {
                for try await status in self {
                    if case .finished(let response) = status {
                        return response
                    }
                }
                preconditionFailure("StatusStream must yield .finished before ending")
            }
        }

        func makeAsyncIterator() -> Iterator {
            Iterator(stream.makeAsyncIterator())
        }

        struct Iterator: AsyncIteratorProtocol {
            private var iterator: AsyncStream<Result<CTAP.Status<Response>, CTAP.SessionError>>.AsyncIterator

            fileprivate init(_ iterator: AsyncStream<Result<CTAP.Status<Response>, CTAP.SessionError>>.AsyncIterator) {
                self.iterator = iterator
            }

            mutating func next() async throws(CTAP.SessionError) -> CTAP.Status<Response>? {
                guard let result = await iterator.next() else {
                    return nil
                }
                switch result {
                case .success(let status):
                    return status
                case .failure(let error):
                    throw error
                }
            }
        }
    }
}

extension CTAP.StatusStream {
    /// Continuation type for building status streams.
    struct Continuation: Sendable {
        private let continuation: AsyncStream<Result<CTAP.Status<Response>, CTAP.SessionError>>.Continuation

        fileprivate init(_ continuation: AsyncStream<Result<CTAP.Status<Response>, CTAP.SessionError>>.Continuation) {
            self.continuation = continuation
        }

        func yield(_ status: CTAP.Status<Response>) {
            continuation.yield(.success(status))
        }

        func yield(error: CTAP.SessionError) {
            continuation.yield(.failure(error))
        }

        func finish() {
            continuation.finish()
        }
    }
}

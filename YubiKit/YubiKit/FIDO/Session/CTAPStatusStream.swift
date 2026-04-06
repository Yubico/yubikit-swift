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

extension CTAP2 {

    /// An async sequence that yields status updates and can throw ``SessionError``.
    ///
    /// This sequence streams ``Status`` updates during long-running CTAP operations.
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
    public struct StatusStream<R: Sendable>: AsyncSequence, @unchecked Sendable {
        public typealias Element = Status<R>

        typealias Base = StatusStreamBase<Status<R>, SessionError>
        typealias Continuation = Base.Continuation

        private let base: Base

        init(_ build: @escaping (Continuation) -> Void) {
            self.base = Base(build)
        }

        init(_ base: Base) {
            self.base = base
        }

        static func error(_ error: SessionError) -> Self {
            Self(Base.error(error))
        }

        /// Consumes the stream and returns the final response value.
        ///
        /// Iterates through all status updates and returns the response
        /// from the `.finished` case. Intermediate status updates are ignored.
        public var value: R {
            get async throws(SessionError) {
                for try await status in self {
                    if case .finished(let response) = status {
                        return response
                    }
                }
                preconditionFailure("StatusStream must yield .finished before ending")
            }
        }

        public func makeAsyncIterator() -> Iterator {
            Iterator(base.makeAsyncIterator())
        }

        public struct Iterator: AsyncIteratorProtocol {
            private var base: Base.Iterator
            private var last: Status<R>?

            fileprivate init(_ base: Base.Iterator) {
                self.base = base
            }

            public mutating func next() async throws(SessionError) -> Status<R>? {
                while true {
                    guard let status = try await base.next() else { return nil }
                    if let last, Status<R>.areDuplicates(last, status) {
                        continue
                    }
                    last = status
                    return status
                }
            }
        }
    }
}

// MARK: - Deduplication

extension CTAP2.Status {
    fileprivate static func areDuplicates(_ lhs: Self, _ rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.processing, .processing), (.waitingForUser, .waitingForUser):
            true
        default:
            false
        }
    }
}

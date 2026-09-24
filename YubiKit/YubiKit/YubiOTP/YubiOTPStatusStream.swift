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

extension YubiOTP {

    /// Status updates for a long-running Yubico OTP operation.
    ///
    /// Only the OTP keyboard transport reports progress. Over SmartCard the stream yields
    /// ``finished(_:)`` alone.
    public enum Status<Response: Sendable>: Sendable {
        /// The YubiKey is processing the command.
        case processing

        /// The YubiKey is waiting for the user to touch it.
        ///
        /// - Parameter cancel: Abandons the command. The stream then throws
        ///   ``SessionError/cancelled(source:)``.
        case waitingForUser(cancel: @Sendable () async -> Void)

        /// The operation completed with a response.
        case finished(Response)
    }

    /// An async sequence that yields ``Status`` updates and can throw ``SessionError``.
    ///
    /// ## Usage
    ///
    /// When you do not need status updates, use ``value``:
    ///
    /// ```swift
    /// let response = try await session.calculateHMACSHA1(challenge: challenge, in: .two).value
    /// ```
    ///
    /// To prompt for touch, or to let the user cancel, iterate the stream:
    ///
    /// ```swift
    /// for try await status in await session.calculateHMACSHA1(challenge: challenge, in: .two) {
    ///     switch status {
    ///     case .processing:
    ///         break
    ///     case .waitingForUser(let cancel):
    ///         showTouchPrompt(onCancel: { Task { await cancel() } })
    ///     case .finished(let response):
    ///         return response
    ///     }
    /// }
    /// ```
    public struct StatusStream<R: Sendable>: AsyncSequence, @unchecked Sendable {
        /// A status update emitted by the sequence.
        public typealias Element = Status<R>

        /// Consumes the stream and returns the final response value.
        ///
        /// Intermediate status updates are ignored.
        public var value: R {
            get async throws(YubiOTP.SessionError) {
                for try await status in self {
                    if case .finished(let response) = status {
                        return response
                    }
                }
                preconditionFailure("StatusStream must yield .finished before ending")
            }
        }

        /// Creates an iterator over the operation's status updates.
        public func makeAsyncIterator() -> Iterator {
            Iterator(base.makeAsyncIterator())
        }

        /// An iterator over Yubico OTP operation status updates.
        public struct Iterator: AsyncIteratorProtocol {
            /// Returns the next distinct status update.
            public mutating func next() async throws(YubiOTP.SessionError) -> Status<R>? {
                while true {
                    guard let status = try await base.next() else { return nil }
                    if let last, Status<R>.areDuplicates(last, status) {
                        continue
                    }
                    last = status
                    return status
                }
            }

            private var base: Base.Iterator
            private var last: Status<R>?

            fileprivate init(_ base: Base.Iterator) {
                self.base = base
            }
        }

        typealias Base = StatusStreamBase<Status<R>, YubiOTP.SessionError>
        typealias Continuation = Base.Continuation

        init(_ build: @escaping (Continuation) -> Void) {
            self.base = Base(build)
        }

        static func error(_ error: YubiOTP.SessionError) -> Self {
            Self(Base.error(error))
        }

        private let base: Base

        private init(_ base: Base) {
            self.base = base
        }
    }
}

extension YubiOTP.Status: StreamStatus {
    var finishedResponse: Response? {
        if case .finished(let response) = self { return response }
        return nil
    }
}

// MARK: - Deduplication

extension YubiOTP.Status {
    fileprivate static func areDuplicates(_ lhs: Self, _ rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.processing, .processing), (.waitingForUser, .waitingForUser):
            true
        default:
            false
        }
    }
}

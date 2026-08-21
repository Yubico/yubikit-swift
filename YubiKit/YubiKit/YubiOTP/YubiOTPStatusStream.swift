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
    /// A slot programmed with `requireTouch` does not answer until the button is pressed, and the
    /// YubiKey reports that wait in the status byte of every feature report. These values mirror
    /// ``CTAP2/Status`` — the OTP protocol uses the same two keep-alive codes as CTAP.
    ///
    /// - Note: Only the OTP keyboard transport reports progress. Over SmartCard the exchange is a
    ///   single blocking APDU, so the stream yields ``finished(_:)`` alone.
    public enum Status<Response: Sendable>: Sendable {
        /// The YubiKey is processing the command.
        case processing

        /// The YubiKey is waiting for the user to touch the button.
        ///
        /// - Parameter cancel: Abandons the command, surfacing as
        ///   ``YubiOTPSessionError/cancelled(source:)``.
        case waitingForUser(cancel: @Sendable () async -> Void)

        /// The operation completed with a response.
        case finished(Response)
    }
}

extension YubiOTP.Status: StreamStatus {
    var finishedResponse: Response? {
        if case .finished(let response) = self { return response }
        return nil
    }
}

extension YubiOTP {

    /// An async sequence that yields ``Status`` updates and can throw ``YubiOTPSessionError``.
    ///
    /// ## Usage
    ///
    /// When touch feedback is not needed, drain the stream with ``value``:
    ///
    /// ```swift
    /// let response = try await session.calculateHMACSHA1(challenge: challenge, in: .two).value
    /// ```
    ///
    /// To prompt for touch, or to allow the user to give up, iterate it:
    ///
    /// ```swift
    /// for try await status in await session.calculateHMACSHA1(challenge: challenge, in: .two) {
    ///     switch status {
    ///     case .processing:
    ///         showSpinner()
    ///     case .waitingForUser(let cancel):
    ///         showTouchPrompt(onCancel: { Task { await cancel() } })
    ///     case .finished(let response):
    ///         return response
    ///     }
    /// }
    /// ```
    public struct StatusStream<R: Sendable>: AsyncSequence, @unchecked Sendable {
        public typealias Element = Status<R>

        typealias Base = StatusStreamBase<Status<R>, YubiOTPSessionError>
        typealias Continuation = Base.Continuation

        private let base: Base

        init(_ build: @escaping (Continuation) -> Void) {
            self.base = Base(build)
        }

        init(_ base: Base) {
            self.base = base
        }

        static func error(_ error: YubiOTPSessionError) -> Self {
            Self(Base.error(error))
        }

        /// Consumes the stream and returns the final response value.
        ///
        /// Intermediate status updates are ignored, so a touch-triggered slot simply blocks until
        /// the button is pressed.
        public var value: R {
            get async throws(YubiOTPSessionError) {
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

            public mutating func next() async throws(YubiOTPSessionError) -> Status<R>? {
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

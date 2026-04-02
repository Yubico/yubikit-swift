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
    /// For simple cases where you don't need status updates, use the ``StatusStream/value`` property:
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
    public typealias StatusStream<R: Sendable> = StatusStreamBase<Status<R>, SessionError>
}

// MARK: - CTAP2 Value Accessor

extension StatusStreamBase where Failure == CTAP2.SessionError {

    /// Consumes the stream and returns the final response value.
    ///
    /// Iterates through all status updates and returns the response
    /// from the `.finished` case. Intermediate status updates are ignored.
    public var value: Status.Response {
        get async throws(Failure) {
            for try await status in self {
                if let response = status.finishedResponse {
                    return response
                }
            }
            preconditionFailure("StatusStream must yield .finished before ending")
        }
    }
}

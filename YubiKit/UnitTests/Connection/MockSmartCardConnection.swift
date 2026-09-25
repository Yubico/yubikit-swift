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

@testable import YubiKit

/// A `SmartCardConnection` test double that answers `send(data:)` with a programmed response
/// for each request, in order. Construct it directly with the test initializer and hand it to
/// `SmartCardInterface(connection:)`; the protocol's required `init()` / `makeConnection()`
/// are unreachable in tests and trap.
final actor MockSmartCardConnection: SmartCardConnection {

    /// The programmed responses, one per `send(data:)` call, each including trailing SW1/SW2.
    private let responses: [Data]
    private var nextResponse = 0

    /// Every request passed to `send(data:)`, in the order they were received.
    private(set) var sentRequests: [Data] = []

    /// Number of `send(data:)` calls observed.
    var sendCount: Int { sentRequests.count }

    /// Create a mock that returns the given responses in sequence, one per `send(data:)` call.
    init(responses: [Data]) {
        self.responses = responses
    }

    // MARK: - SmartCardConnection

    init() async throws(SmartCardConnectionError) {
        fatalError("use the test initializer")
    }

    static func makeConnection() async throws(SmartCardConnectionError) -> MockSmartCardConnection {
        fatalError("use the test initializer")
    }

    @discardableResult
    func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        sentRequests.append(data)
        precondition(nextResponse < responses.count, "MockSmartCardConnection ran out of programmed responses")
        defer { nextResponse += 1 }
        return responses[nextResponse]
    }

    // MARK: - Connection

    func close(error: Error?) async {}

    func waitUntilClosed() async -> Error? { nil }
}

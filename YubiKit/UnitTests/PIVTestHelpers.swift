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
import Testing

@testable import YubiKit

// Responses include status bytes. Recorded requests start after session initialization.
func makePIVSession(
    firmware: String,
    responses: [Data]
) async throws -> (session: PIVSession, connection: MockSmartCardConnection) {
    let version = try #require(Version(firmware))
    let setupResponses = [
        Data([0x90, 0]),  // Select PIV.
        Data([version.major, version.minor, version.micro, 0x90, 0]),  // Read PIV version.
    ]
    let connection = MockSmartCardConnection(responses: setupResponses + responses)
    let session = try await PIVSession.makeSession(connection: connection)
    // Setup must not consume a response intended for the operation under test.
    try #require(await connection.sendCount == setupResponses.count)
    await connection.clearRequests()
    return (session, connection)
}

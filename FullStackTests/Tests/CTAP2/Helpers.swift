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

@testable import FullStackTests
@testable import YubiKit

let defaultTestPin = "11234567"

#if os(macOS)
func withCTAP2Session<T>(
    _ body: (FIDO2Session) async throws -> T
) async throws -> T {
    let connection = try await HIDFIDOConnection.makeConnection()
    let session = try await CTAP2.Session.makeSession(connection: connection)
    let result = try await body(session)
    await connection.close(error: nil)
    return result
}

#elseif os(iOS)
func withCTAP2Session<T>(
    _ body: (FIDO2SessionOverSmartCard) async throws -> T
) async throws -> T {
    let connection = try await TestableConnection.create(with: .nfc)
    let session = try await CTAP2.Session.makeSession(connection: connection)
    let result = try await body(session)
    await connection.close(error: nil)
    return result
}
#endif

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

import CryptoTokenKit
import Foundation
import Testing

@testable import YubiKit

struct OATHCalculateCodesTests {
    @Test func recalculatesOnlyCustomPeriods() async throws {
        func entry(_ name: String, tag: TKTLVTag, value: Data = Data()) -> Data {
            TKBERTLVRecord(tag: 0x71, value: Data(name.utf8)).data + TKBERTLVRecord(tag: tag, value: value).data
        }

        let success = Data([0x90, 0x00])
        let bulkCode = Data([6, 0, 0, 0, 1])
        let bulk =
            entry("default", tag: 0x76, value: bulkCode)
            + entry("30/explicit", tag: 0x76, value: bulkCode)
            + entry("60/custom", tag: 0x76, value: bulkCode)
            + entry("counter", tag: 0x77)
            + entry("touch", tag: 0x7c)
        let individual = TKBERTLVRecord(tag: 0x76, value: Data([6, 0, 0, 0, 2])).data + success
        let select = Data([0x79, 3, 5, 7, 1, 0x71, 1, 42]) + success
        let connection = MockSmartCardConnection(responses: [select, bulk + success, individual, individual])
        let session = try await OATHSession.makeSession(connection: connection)
        await connection.clearRequests()

        let results = try await session.calculateCredentialCodes(timestamp: Date(timeIntervalSince1970: 120))

        #expect(results.map { $0.1?.code } == ["000001", "000001", "000002", nil, nil])
        let requests = await connection.sentRequests
        #expect(requests.map { $0[1] } == [0xa4, 0xa2])
    }
}

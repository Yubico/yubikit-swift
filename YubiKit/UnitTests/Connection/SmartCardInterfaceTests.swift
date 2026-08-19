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

/// Unit coverage for `SmartCardInterface`'s multi-frame APDU reassembly. When a card answers with
/// SW1=0x61 (more data), the interface issues a GET RESPONSE APDU and accumulates payload until it
/// sees SW=0x9000. This was previously only exercised by the `OATH.Calculate.chunkedData`
/// integration scenario.
@Suite("SmartCardInterface multi-frame reassembly")
struct SmartCardInterfaceTests {

    /// Minimal SELECT reply that lets `SmartCardInterface(application: .oath)` init succeed:
    /// any payload terminated by SW=0x9000.
    private static let selectSuccess = Data([0x01, 0x02, 0x90, 0x00])

    private let testApdu = APDU(cla: 0x00, ins: 0x01, p1: 0x00, p2: 0x00)

    @Test("a two-frame response is reassembled across one GET RESPONSE")
    func twoFrameReassembly() async throws {
        let chunk1 = Data([0xaa, 0xbb, 0xcc])
        let chunk2 = Data([0xdd, 0xee])

        let mock = MockSmartCardConnection(responses: [
            Self.selectSuccess,
            // frame 1: <chunk1> 0x61 0x02 (two more bytes available)
            chunk1 + Data([0x61, UInt8(chunk2.count)]),
            // frame 2: <chunk2> 0x90 0x00 (done)
            chunk2 + Data([0x90, 0x00]),
        ])

        let interface = try await SmartCardInterface<OATHSessionError>(connection: mock, application: .oath)
        let result: Data = try await interface.send(apdu: testApdu)

        #expect(result == chunk1 + chunk2)

        // 1 SELECT + 1 command + 1 GET RESPONSE.
        let count = await mock.sendCount
        #expect(count == 3)

        // The continuation request is the default GET RESPONSE: 00 C0 00 00 00.
        let requests = await mock.sentRequests
        #expect(requests[2] == Data([0x00, 0xc0, 0x00, 0x00, 0x00]))
    }

    @Test("a three-frame response iterates the continuation loop twice")
    func threeFrameReassembly() async throws {
        let chunk1 = Data([0x11, 0x22])
        let chunk2 = Data([0x33, 0x44, 0x55])
        let chunk3 = Data([0x66])

        let mock = MockSmartCardConnection(responses: [
            Self.selectSuccess,
            chunk1 + Data([0x61, UInt8(chunk2.count)]),
            chunk2 + Data([0x61, UInt8(chunk3.count)]),
            chunk3 + Data([0x90, 0x00]),
        ])

        let interface = try await SmartCardInterface<OATHSessionError>(connection: mock, application: .oath)
        let result: Data = try await interface.send(apdu: testApdu)

        #expect(result == chunk1 + chunk2 + chunk3)

        // 1 SELECT + 1 command + 2 GET RESPONSE.
        let count = await mock.sendCount
        #expect(count == 4)

        let requests = await mock.sentRequests
        #expect(requests[2] == Data([0x00, 0xc0, 0x00, 0x00, 0x00]))
        #expect(requests[3] == Data([0x00, 0xc0, 0x00, 0x00, 0x00]))
    }

    @Test("the OATH continuation instruction 0xa5 is used when requested")
    func oathContinuationInstruction() async throws {
        let chunk1 = Data([0x01, 0x02, 0x03])
        let chunk2 = Data([0x04, 0x05, 0x06, 0x07])

        let mock = MockSmartCardConnection(responses: [
            Self.selectSuccess,
            chunk1 + Data([0x61, UInt8(chunk2.count)]),
            chunk2 + Data([0x90, 0x00]),
        ])

        // OATH selects/sends with insSendRemaining 0xa5 (see SmartCardSession).
        let interface = try await SmartCardInterface<OATHSessionError>(
            connection: mock,
            application: .oath,
            insSendRemaining: 0xa5
        )
        let result: Data = try await interface.send(apdu: testApdu, insSendRemaining: 0xa5)

        #expect(result == chunk1 + chunk2)

        let requests = await mock.sentRequests
        // The GET RESPONSE uses the OATH continuation instruction byte: 00 A5 00 00 00.
        #expect(requests[2] == Data([0x00, 0xa5, 0x00, 0x00, 0x00]))
    }
}

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

// Failure modes: absent, zero, or empty continuation stops; a positive count reads every
// declared page; oversized counts, undecodable values, bad lengths, and bad TLVs fail.
struct ManagementDeviceInfoTests {
    private func frame(_ tlvs: [UInt8]) -> Data {
        Data([UInt8(tlvs.count)] + tlvs + [0x90, 0x00])
    }

    private func connection(_ pages: [Data]) -> MockSmartCardConnection {
        MockSmartCardConnection(responses: [Data("5.7.0".utf8) + Data([0x90, 0x00])] + pages)
    }

    private func read(_ connection: MockSmartCardConnection) async throws -> DeviceInfo {
        let session = try await Management.Session.makeSession(connection: connection)
        return try await session.getDeviceInfo()
    }

    private func pagesRead(_ connection: MockSmartCardConnection) async -> [UInt8] {
        let requests = await connection.sentRequests
        return requests.dropFirst().map { $0[2] }
    }

    private func expectParseError(_ pages: [Data]) async {
        do {
            _ = try await read(connection(pages))
            Issue.record("Malformed device info was accepted")
        } catch let error as ManagementSessionError {
            guard case .responseParseError = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("missing, zero, and empty continuation values stop after the first page")
    func terminalFirstPage() async throws {
        let cases: [[UInt8]] = [[], [0x10, 0x01, 0], [0x10, 0]]
        for tlvs in cases {
            let card = connection([frame(tlvs)])
            let info = try await read(card)
            #expect(info.version == Version("5.7.0")!)
            #expect(await pagesRead(card) == [0])
        }
    }

    @Test("one continuation reads page one and merges its fields")
    func oneContinuation() async throws {
        let card = connection([frame([0x10, 0x01, 1]), frame([0x02, 0x01, 0x2a])])
        let info = try await read(card)
        #expect(info.serialNumber == 42)
        #expect(await pagesRead(card) == [0, 1])
    }

    @Test("two declared pages remain scheduled when the middle page omits the marker")
    func twoContinuations() async throws {
        let card = connection([
            frame([0x10, 0x01, 2]),
            frame([0x01, 0x01, 0x3b]),
            frame([0x02, 0x01, 0x2a]),
        ])
        let info = try await read(card)
        #expect(info.serialNumber == 42)
        #expect(info.supportedCapabilities[.usb] == 0x3b)
        #expect(await pagesRead(card) == [0, 1, 2])
    }

    @Test("an overlong continuation value is a parse error")
    func malformedContinuation() async {
        await expectParseError([frame([0x10, 9] + [UInt8](repeating: 0, count: 9))])
    }

    @Test("a continuation count cannot pass the last one-byte page number")
    func excessiveContinuation() async {
        await expectParseError([frame([0x10, 2, 1, 0])])
        await expectParseError([frame([0x10, 1, 1]), frame([0x10, 1, 0xff])])
    }

    @Test("invalid outer length and malformed TLV payload are parse errors")
    func malformedPayload() async {
        await expectParseError([Data([2, 0x02, 1, 0x2a, 0x90, 0])])
        await expectParseError([frame([0x02, 2, 0x2a])])
    }
}

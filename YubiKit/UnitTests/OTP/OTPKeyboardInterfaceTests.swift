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

struct OTPKeyboardInterfaceTests {

    @Test("a data command round-trips and its CRC validates")
    func dataResponseRoundTrips() async throws {
        let connection = try await FakeOTPConnection()
        connection.serial = 12_345_678
        let interface = try await OTPKeyboardInterface(connection: connection)

        let response = try await interface.sendAndReceive(slot: FakeOTPConnection.slotDeviceSerial)

        #expect(response.prefix(6).hasValidCRC16)
        #expect(response.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) } == 12_345_678)
    }

    @Test("all-zero middle chunks are skipped but the first and last are always sent")
    func skipsAllZeroChunks() async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await OTPKeyboardInterface(connection: connection)

        _ = try await interface.sendAndReceive(slot: FakeOTPConnection.slotDeviceSerial)

        #expect(connection.writtenChunkSequences == [0, 9])
    }

    @Test("a full 64-byte payload sends every chunk")
    func fullPayloadSendsAllChunks() async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await OTPKeyboardInterface(connection: connection)

        _ = try await interface.sendAndReceive(
            slot: FakeOTPConnection.slotConfig1,
            data: Data(repeating: 0xAB, count: 64)
        )

        #expect(connection.writtenChunkSequences == Array(0...9))
    }

    @Test("deleting the last configured slot resets the programming sequence to zero")
    func programmingSequenceResetIsAccepted() async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await OTPKeyboardInterface(connection: connection)
        _ = try await interface.sendAndReceive(
            slot: FakeOTPConnection.slotConfig1,
            data: Data(repeating: 0x11, count: 52)
        )

        let status = try await interface.sendAndReceive(slot: FakeOTPConnection.slotConfig1, data: Data(count: 52))

        #expect(status[3] == 0)
        #expect(status[4] & 0x03 == 0)
    }

    @Test("a command that the key does not acknowledge is rejected")
    func unacknowledgedCommandIsRejected() async throws {
        let interface = try await OTPKeyboardInterface(connection: try await FakeOTPConnection())
        do {
            _ = try await interface.sendAndReceive(slot: FakeOTPConnection.slotUnknown)
            Issue.record("An unacknowledged command was accepted")
        } catch .commandRejected {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("an oversized payload is rejected before any report is sent")
    func oversizedPayloadRejected() async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await OTPKeyboardInterface(connection: connection)
        do {
            _ = try await interface.sendAndReceive(slot: FakeOTPConnection.slotConfig1, data: Data(count: 65))
            Issue.record("An oversized payload was accepted")
        } catch .illegalArgument {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(connection.writtenReports.isEmpty)
    }
}

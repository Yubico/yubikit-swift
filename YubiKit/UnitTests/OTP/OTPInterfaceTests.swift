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

/// Frame-protocol behaviour, checked against ``FakeOTPConnection`` (a port of the digital twin's
/// keyboard transport). Mirrors the invariants in `yubikit.core.otp.OtpProtocol`.
struct OTPInterfaceTests {

    private func makeInterface(
        _ connection: FakeOTPConnection
    ) async throws -> OTPInterface<YubiOTPSessionError> {
        try await OTPInterface<YubiOTPSessionError>(connection: connection)
    }

    @Test("the interface parses the firmware version from the status report on connect")
    func parsesVersion() async throws {
        let connection = try await FakeOTPConnection()
        connection.firmware = [5, 7, 4]
        let interface = try await makeInterface(connection)
        #expect(await interface.version == Version(withData: Data([5, 7, 4])))
    }

    @Test("a data command round-trips and its CRC validates")
    func dataResponseRoundTrips() async throws {
        let connection = try await FakeOTPConnection()
        connection.serial = 12_345_678
        let interface = try await makeInterface(connection)

        let response = try await interface.sendAndReceive(slot: FakeOTPConnection.slotDeviceSerial)

        // Raw data response: 4 serial bytes plus the CRC trailer.
        #expect(response.count >= 6)
        #expect(response.prefix(6).hasValidCRC16)
        let serial = response.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        #expect(serial == 12_345_678)
    }

    @Test("all-zero middle chunks are skipped but the first and last are always sent")
    func skipsAllZeroChunks() async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await makeInterface(connection)

        // An empty payload: only the edge reports plus the one carrying slot+CRC should go out.
        _ = try await interface.sendAndReceive(slot: FakeOTPConnection.slotDeviceSerial)

        let sequences = connection.writtenChunkSequences
        // Chunk 0 is all-zero but is an edge, so it is sent anyway; chunks 1-8 are all-zero and
        // skipped; chunk 9 carries slot ‖ crc ‖ filler and is never all-zero.
        #expect(sequences == [0, 9], "an empty payload should send only the edge chunks, sent \(sequences)")
    }

    @Test("a full 64-byte payload sends every chunk")
    func fullPayloadSendsAllChunks() async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await makeInterface(connection)

        _ = try await interface.sendAndReceive(
            slot: FakeOTPConnection.slotConfig1,
            data: Data(repeating: 0xAB, count: 64)
        )

        let sequences = connection.writtenChunkSequences
        #expect(sequences == Array(0...9), "a fully populated frame should send all ten chunks")
    }

    @Test("a configuration write returns the updated status with an advanced programming sequence")
    func configWriteAdvancesProgrammingSequence() async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await makeInterface(connection)

        let before = try await interface.readStatus()
        let status = try await interface.sendAndReceive(
            slot: FakeOTPConnection.slotConfig1,
            data: Data(repeating: 0x11, count: 52)
        )

        #expect(status.count == 6)
        #expect(status[3] == before[3] + 1, "programming sequence should advance by one")
        #expect(status[4] & 0x01 != 0, "slot 1 should report as configured")
    }

    @Test("deleting the last configured slot resets the programming sequence to zero")
    func programmingSequenceResetIsAccepted() async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await makeInterface(connection)

        // Drive the sequence to 0xFF so the next write wraps to 0 — the reset-to-zero case that
        // `_is_sequence_updated` has to accept when both slots end up empty.
        for _ in 0..<0xFF {
            _ = try await interface.sendAndReceive(
                slot: FakeOTPConnection.slotConfig1,
                data: Data(repeating: 0x11, count: 52)
            )
        }
        let status = try await interface.sendAndReceive(
            slot: FakeOTPConnection.slotConfig1,
            data: Data(count: 52)  // all-zero config = delete
        )
        #expect(status[3] == 0, "programming sequence should have wrapped to zero")
        #expect(status[4] & 0x03 == 0, "no slot should remain configured")
    }

    @Test("a command the key ignores is reported as rejected")
    func unknownCommandIsRejected() async throws {
        let interface = try await makeInterface(try await FakeOTPConnection())

        await #expect(throws: YubiOTPSessionError.self) {
            _ = try await interface.sendAndReceive(slot: FakeOTPConnection.slotUnknown)
        }
    }

    @Test("the frame CRC covers the payload only, and the device accepts it")
    func frameCRCIsAccepted() async throws {
        // Regression guard: computing the CRC over payload+slot instead of payload alone passes
        // against the digital twin (which never checks it) but is rejected by real hardware.
        let connection = try await FakeOTPConnection()
        let interface = try await makeInterface(connection)

        _ = try await interface.sendAndReceive(slot: FakeOTPConnection.slotDeviceSerial)
        #expect(connection.rejectedFrameCount == 0, "the device should accept the frame's CRC")

        _ = try await interface.sendAndReceive(
            slot: FakeOTPConnection.slotConfig1,
            data: Data(repeating: 0xAB, count: 52)
        )
        #expect(connection.rejectedFrameCount == 0, "a populated frame should also carry a valid CRC")
    }

    @Test("an oversized payload is rejected before touching the transport")
    func oversizedPayloadRejected() async throws {
        let connection = try await FakeOTPConnection()
        let interface = try await makeInterface(connection)
        let writesBefore = connection.writtenReports.count

        await #expect(throws: YubiOTPSessionError.self) {
            _ = try await interface.sendAndReceive(slot: 0x01, data: Data(count: 65))
        }
        #expect(connection.writtenReports.count == writesBefore, "nothing should be written")
    }
}

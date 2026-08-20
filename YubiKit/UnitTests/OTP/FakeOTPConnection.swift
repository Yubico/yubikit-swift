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

/// A software YubiKey speaking the OTP keyboard frame protocol, ported from the digital twin's
/// `src/twin/transports/keyboard.py`. Using the twin's logic rather than a hand-rolled mock keeps
/// these tests an independent oracle instead of an echo of the implementation under test.
final class FakeOTPConnection: OTPConnection, @unchecked Sendable {

    // Slot commands understood by the fake.
    static let slotConfig1: UInt8 = 0x01
    static let slotConfig2: UInt8 = 0x03
    static let slotDeviceSerial: UInt8 = 0x10
    static let slotUnknown: UInt8 = 0x7F

    /// Every report the host wrote, in order — lets tests assert the chunking rules directly.
    private(set) var writtenReports: [[UInt8]] = []

    /// Sequence numbers of the frame-chunk writes, excluding the `00×7 ‖ 0xFF` reset sentinel
    /// (which also has the write bit set, but is not part of a frame).
    var writtenChunkSequences: [UInt8] {
        writtenReports
            .filter { $0[7] != 0xFF && $0[7] & 0x80 != 0 }
            .map { $0[7] & 0x1F }
    }

    /// Frames rejected for a bad CRC — a framing bug shows up here rather than as a silent pass.
    private(set) var rejectedFrameCount = 0

    var serial: UInt32 = 12_345_678
    var firmware: [UInt8] = [5, 7, 4]

    private var frame = [UInt8](repeating: 0, count: 70)
    private var outbox: [[UInt8]] = []
    private var programmingSequence: UInt8 = 0
    private var slots: [Data?] = [nil, nil]
    private let lock = NSLock()

    required init() async throws(OTPConnectionError) {}

    static func makeConnection() async throws(OTPConnectionError) -> FakeOTPConnection {
        try await FakeOTPConnection()
    }

    // MARK: - OTPConnection

    func send(_ report: Data) async throws(OTPConnectionError) {
        lock.with { writeReport(Array(report)) }
    }

    func receive() async throws(OTPConnectionError) -> Data {
        lock.with {
            if !outbox.isEmpty { return Data(outbox.removeFirst()) }
            return Data([0] + status + [0])
        }
    }

    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }

    // MARK: - Device behaviour

    /// `version[3] ‖ pgmSeq ‖ configState[2, LE]`
    private var status: [UInt8] {
        let state = configState
        return firmware + [programmingSequence, UInt8(state & 0xFF), UInt8(state >> 8)]
    }

    private var configState: UInt16 {
        var state: UInt16 = 0
        if slots[0] != nil { state |= 0x01 }
        if slots[1] != nil { state |= 0x02 }
        return state
    }

    private func writeReport(_ report: [UInt8]) {
        guard report.count == 8 else { return }
        writtenReports.append(report)

        let flag = report[7]
        if flag == 0xFF {  // host aborting or draining a read
            frame = [UInt8](repeating: 0, count: 70)
            outbox.removeAll()
            return
        }
        guard flag & 0x80 != 0 else { return }

        let sequence = Int(flag & 0x1F)
        let offset = sequence * 7
        if offset + 7 <= 70 {
            frame.replaceSubrange(offset..<(offset + 7), with: report[0..<7])
        }
        if sequence == 9 {
            let completed = frame
            frame = [UInt8](repeating: 0, count: 70)
            dispatch(completed)
        }
    }

    private func dispatch(_ frame: [UInt8]) {
        let payload = Data(frame[0..<64])
        let slot = frame[64]

        // Real silicon validates the frame CRC and rejects a bad one. The twin's keyboard transport
        // does not, so this check is deliberately stricter than the twin — it is the only place a
        // framing error is caught before hardware.
        let crc = UInt16(frame[65]) | UInt16(frame[66]) << 8
        guard crc == payload.crc16 else {
            rejectedFrameCount += 1
            return  // no data, no programming-sequence bump: the host sees a rejection
        }

        switch slot {
        case Self.slotDeviceSerial:
            queue(
                Data([
                    UInt8(serial >> 24 & 0xFF), UInt8(serial >> 16 & 0xFF),
                    UInt8(serial >> 8 & 0xFF), UInt8(serial & 0xFF),
                ])
            )
        case Self.slotConfig1, Self.slotConfig2:
            let index = slot == Self.slotConfig2 ? 1 : 0
            slots[index] = payload.contains(where: { $0 != 0 }) ? payload : nil
            programmingSequence &+= 1
        default:
            break  // unknown command: no data, no programming-sequence bump
        }
    }

    /// Chunk a data response into 7-byte reports flagged `RESP_PENDING | seq`, terminated by a
    /// sequence-zero report. The trailer is the complement of the CRC, little-endian.
    private func queue(_ data: Data) {
        var body = Array(data.appendingCRC16)
        var sequence: UInt8 = 0
        while !body.isEmpty {
            let chunk = Array(body.prefix(7))
            body.removeFirst(chunk.count)
            outbox.append(chunk + [UInt8](repeating: 0, count: 7 - chunk.count) + [0x40 | sequence])
            sequence += 1
        }
        outbox.append([UInt8](repeating: 0, count: 7) + [0x40])
    }
}

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

final class FakeOTPConnection: OTPConnection, @unchecked Sendable {

    static let slotConfig1: UInt8 = 0x01
    static let slotConfig2: UInt8 = 0x03
    static let slotDeviceSerial: UInt8 = 0x10
    static let slotChallengeHMAC1: UInt8 = 0x30
    static let slotChallengeHMAC2: UInt8 = 0x38
    static let slotUnknown: UInt8 = 0x7F

    private(set) var writtenReports: [[UInt8]] = []

    var writtenChunkSequences: [UInt8] {
        writtenReports
            .filter { $0[7] != 0xFF && $0[7] & 0x80 != 0 }
            .map { $0[7] & 0x1F }
    }

    var dispatchedCommands: [UInt8] { lock.with { dispatchedSlots } }

    var dispatchedPayloads: [Data] { lock.with { payloads } }

    var serial: UInt32 = 12_345_678
    var firmware: [UInt8] = [5, 7, 4]

    var touchReportsBeforeResponse = 0

    var hmacResponse = Data(repeating: 0xAB, count: 20)

    var corruptsResponseCRC = false

    private var frame = [UInt8](repeating: 0, count: 70)
    private var outbox: [[UInt8]] = []
    private var dispatchedSlots: [UInt8] = []
    private var payloads: [Data] = []
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
        dispatchedSlots.append(slot)
        payloads.append(payload)

        // Like the YubiKey, ignore a frame with a bad CRC: the host sees a rejection.
        let crc = UInt16(frame[65]) | UInt16(frame[66]) << 8
        guard crc == payload.crc16 else { return }

        switch slot {
        case Self.slotDeviceSerial:
            queue(
                Data([
                    UInt8(serial >> 24 & 0xFF), UInt8(serial >> 16 & 0xFF),
                    UInt8(serial >> 8 & 0xFF), UInt8(serial & 0xFF),
                ])
            )
        case Self.slotChallengeHMAC1, Self.slotChallengeHMAC2:
            for _ in 0..<touchReportsBeforeResponse {
                outbox.append([UInt8](repeating: 0, count: 7) + [0x20])
            }
            queue(hmacResponse)
        case Self.slotConfig1, Self.slotConfig2:
            let index = slot == Self.slotConfig2 ? 1 : 0
            let hadConfiguredSlot = configState & 0x03 != 0
            slots[index] = payload.contains(where: { $0 != 0 }) ? payload : nil
            if hadConfiguredSlot, configState & 0x03 == 0 {
                programmingSequence = 0
            } else {
                programmingSequence &+= 1
            }
        default:
            break  // unknown command: no data, no programming-sequence bump
        }
    }

    private func queue(_ data: Data) {
        var body = Array(data.appendingCRC16)
        if corruptsResponseCRC { body[body.count - 1] ^= 0xFF }
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

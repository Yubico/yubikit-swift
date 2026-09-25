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
import Logging

// The frame protocol of the OTP keyboard HID interface. A command is a 70-byte frame sent as
// 8-byte feature reports; the YubiKey answers with data reports, or with a status report whose
// programming sequence acknowledges a write.
final actor OTPKeyboardInterface: HasOTPLogger {

    let version: Version

    // The most recent status struct.
    private(set) var status: Data

    init(connection: OTPConnection) async throws(YubiOTP.SessionError) {
        let status = Self.status(in: try await Self.receiveReport(from: connection))
        self.connection = connection
        self.version = Version(withData: status.prefix(3))!.resolvingDevelopment
        self.status = status
        logger.debug("OTP interface initialized", metadata: ["version": .stringConvertible(version)])
    }

    func readStatus() async throws(YubiOTP.SessionError) -> Data {
        logger.debug("Reading OTP status")
        status = Self.status(in: try await receiveReport())
        return status
    }

    // Returns the response data, or the status struct when the command acknowledged a write.
    func sendAndReceive(
        slot: UInt8,
        data: Data = Data(),
        operationID: UUID? = nil,
        onKeepalive: (@Sendable (_ waitingForTouch: Bool) -> Void)? = nil
    ) async throws(YubiOTP.SessionError) -> Data {
        isCancelled = false
        activeOperationID = operationID
        defer { activeOperationID = nil }
        logger.debug(
            "Sending OTP slot command",
            metadata: ["command": .stringConvertible(slot), "bytes": .stringConvertible(data.count)]
        )
        guard data.count <= slotDataSize else {
            throw .illegalArgument("Payload of \(data.count) bytes is too large for an OTP frame", source: .here())
        }

        // payload[64] ‖ slot ‖ crc16(payload) ‖ filler[3]. The CRC covers the padded payload only.
        var frame = data
        frame.append(Data(count: slotDataSize - data.count))
        let crc = frame.crc16
        frame.append(slot)
        frame.append(contentsOf: [UInt8(crc & 0xFF), UInt8(crc >> 8)])
        frame.append(Data(count: 3))

        let programmingSequence = try await sendFrame(Array(frame))
        return try await readFrame(previousProgrammingSequence: programmingSequence, onKeepalive: onKeepalive)
    }

    // Abandons an in-flight command at the polling loop's next suspension point.
    func cancel(operationID: UUID) {
        guard activeOperationID == operationID else { return }
        logger.debug("Requesting OTP command cancellation")
        isCancelled = true
    }

    // MARK: - Private

    private let connection: OTPConnection

    // Set by cancel(operationID:) and observed by the polling loop between reports.
    private var isCancelled = false
    private var activeOperationID: UUID?

    private func sendFrame(_ frame: [UInt8]) async throws(YubiOTP.SessionError) -> UInt8 {
        let programmingSequence = Self.status(in: try await receiveReport())[statusOffsetProgrammingSequence]
        let reportCount = frameSize / reportDataSize

        for sequence in 0..<reportCount {
            let start = sequence * reportDataSize
            let chunk = Array(frame[start..<(start + reportDataSize)])

            // All-zero chunks are skipped, except the first and last, which frame the transfer.
            let isEdge = sequence == 0 || sequence == reportCount - 1
            guard isEdge || chunk.contains(where: { $0 != 0 }) else { continue }

            try await awaitReadyToWrite()
            try await sendReport(chunk + [slotWriteFlag | UInt8(sequence)])
        }
        return programmingSequence
    }

    private func readFrame(
        previousProgrammingSequence: UInt8,
        onKeepalive: (@Sendable (_ waitingForTouch: Bool) -> Void)?
    ) async throws(YubiOTP.SessionError) -> Data {
        var response = Data()
        var expectedSequence: UInt8 = 0
        var needsTouch = false

        while true {
            let report = try await receiveReport()
            let statusByte = report[reportDataSize]

            if statusByte & responsePendingFlag != 0 {
                let sequence = statusByte & sequenceMask
                if sequence == expectedSequence {
                    response.append(contentsOf: report[0..<reportDataSize])
                    expectedSequence += 1
                } else if sequence == 0 {
                    // The sequence restarted at zero: the transfer is complete.
                    try await resetState()
                    logger.debug("Received OTP data response", metadata: ["bytes": .stringConvertible(response.count)])
                    return response
                }
            } else if statusByte == 0 {
                guard response.isEmpty else {
                    throw .responseParseError("OTP data response ended mid-transfer", source: .here())
                }
                let status = Self.status(in: report)
                if isProgrammingSequenceUpdated(status, previous: previousProgrammingSequence) {
                    self.status = status
                    logger.debug("OTP configuration write acknowledged")
                    return status
                }
                if needsTouch {
                    throw .timeout(source: .here())
                }
                throw .commandRejected("The YubiKey rejected the slot command", source: .here())
            } else {
                // Busy. A pending touch is reported with the timeout-wait flag.
                if statusByte & responseTimeoutWaitFlag != 0 {
                    if !needsTouch {
                        logger.debug("OTP command waiting for touch")
                    }
                    needsTouch = true
                    onKeepalive?(true)
                } else {
                    onKeepalive?(false)
                }
                try? await Task.sleep(for: needsTouch ? touchPollInterval : processingPollInterval)
                // Checked after the sleep, which is where cancel(operationID:) gets a chance to run.
                if isCancelled || Task.isCancelled {
                    isCancelled = false
                    try await resetState()
                    logger.debug("OTP command cancelled")
                    throw .cancelled(source: .here())
                }
            }
        }
    }

    // A write advances the programming sequence, except that deleting the last configured slot
    // resets it to zero.
    private func isProgrammingSequenceUpdated(_ status: Data, previous: UInt8) -> Bool {
        let next = status[statusOffsetProgrammingSequence]
        if next == previous &+ 1 { return true }
        return next == 0 && previous > 0 && status[statusOffsetConfigState] & configSlotsProgrammedMask == 0
    }

    private func awaitReadyToWrite() async throws(YubiOTP.SessionError) {
        for _ in 0..<readyPollAttempts {
            if try await receiveReport()[reportDataSize] & slotWriteFlag == 0 { return }
            try? await Task.sleep(for: readyPollInterval)
            guard !Task.isCancelled else { throw .cancelled(source: .here()) }
        }
        throw .timeout(source: .here())
    }

    // Tells the key to abandon any in-flight response.
    private func resetState() async throws(YubiOTP.SessionError) {
        try await sendReport([UInt8](repeating: 0, count: reportDataSize) + [0xFF])
    }

    private func receiveReport() async throws(YubiOTP.SessionError) -> [UInt8] {
        try await Self.receiveReport(from: connection)
    }

    private func sendReport(_ report: [UInt8]) async throws(YubiOTP.SessionError) {
        do {
            try await connection.send(Data(report))
        } catch {
            throw .otpConnectionError(error, source: .here())
        }
    }

    private static func receiveReport(from connection: OTPConnection) async throws(YubiOTP.SessionError) -> [UInt8] {
        let report: Data
        do {
            report = try await connection.receive()
        } catch {
            throw .otpConnectionError(error, source: .here())
        }
        guard report.count == otpFeatureReportSize else {
            throw .responseParseError(
                "Expected an \(otpFeatureReportSize)-byte feature report, got \(report.count)",
                source: .here()
            )
        }
        return Array(report)
    }

    // A report carries the status struct between a reserved first byte and the status byte.
    private static func status(in report: [UInt8]) -> Data {
        Data(report[1..<reportDataSize])
    }
}

// MARK: - Frame protocol constants

private let reportDataSize = otpFeatureReportSize - 1
private let slotDataSize = 64
// payload(64) ‖ slot(1) ‖ crc(2) ‖ filler(3)
private let frameSize = slotDataSize + 6

private let responsePendingFlag: UInt8 = 0x40  // the report carries response data
private let slotWriteFlag: UInt8 = 0x80  // set by the host, cleared by the key
private let responseTimeoutWaitFlag: UInt8 = 0x20  // the key is waiting for touch
private let sequenceMask: UInt8 = 0x1F
private let configSlotsProgrammedMask: UInt8 = 0b0000_0011

// Up to ~1s waiting for the key to clear the write flag.
private let readyPollAttempts = 20
private let readyPollInterval = Duration.milliseconds(50)
private let processingPollInterval = Duration.milliseconds(20)
private let touchPollInterval = Duration.milliseconds(100)

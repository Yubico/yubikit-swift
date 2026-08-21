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

// MARK: - Frame protocol constants

// Seven payload bytes per report; the eighth carries the sequence/status flags.
private let reportDataSize = otpFeatureReportSize - 1
// A slot command payload is always padded to 64 bytes.
private let slotDataSize = 64
// payload(64) ‖ slot(1) ‖ crc(2) ‖ filler(3)
private let frameSize = slotDataSize + 6

private let respPendingFlag: UInt8 = 0x40  // report carries response data
private let slotWriteFlag: UInt8 = 0x80  // set by host, cleared by the key
private let respTimeoutWaitFlag: UInt8 = 0x20  // key is waiting for touch
private let sequenceMask: UInt8 = 0x1F

private let statusOffsetProgSeq = 4
private let statusOffsetTouchLow = 5
private let configSlotsProgrammedMask: UInt8 = 0b0000_0011

// Up to ~1s waiting for the key to clear SLOT_WRITE_FLAG.
private let readyPollAttempts = 20
private let readyPollInterval = Duration.milliseconds(50)
// Poll intervals while the key reports it is busy, mirroring yubikit.core.otp.
private let processingPollInterval = Duration.milliseconds(20)
private let touchPollInterval = Duration.milliseconds(100)

/// Keep-alive codes reported while a command is in flight. The OTP protocol reuses the CTAP values,
/// so these map straight onto ``YubiOTP/Status``.
let keepaliveProcessing: UInt8 = 0x01
let keepaliveUserPresenceNeeded: UInt8 = 0x02

/// The Yubico OTP frame protocol over an ``OTPConnection``.
///
/// Slot commands travel as a 70-byte frame split into ten 7-byte HID feature reports. The key
/// answers either with chunked data (reads such as the serial number or an HMAC response) or with
/// an updated status struct (configuration writes, detected by the programming sequence advancing).
///
/// This is the OTP analogue of ``FIDOInterface``: it owns framing and nothing else, so the session
/// above it can be transport-agnostic.
public final actor OTPInterface<Error: OTPSessionError>: HasOTPLogger {

    // MARK: - Properties

    public let connection: OTPConnection

    /// The firmware version reported in the key's status struct.
    public private(set) var version: Version = Version(withData: Data([0, 0, 0]))!

    /// The most recent 6-byte status struct: `version[3] ‖ pgmSeq[1] ‖ configState[2, LE]`.
    public private(set) var status: Data = Data(count: 6)

    /// Set by ``cancel()`` and observed by the polling loop between reports.
    private var isCancelled = false

    // MARK: - Initialization

    init(connection: OTPConnection) async throws(Error) {
        self.connection = connection

        let report = try await receiveReport()
        guard let version = Version(withData: Data(report[1..<4])) else {
            throw .responseParseError("Could not parse a firmware version from the OTP status report", source: .here())
        }
        self.version = version
        self.status = Data(report[1..<(otpFeatureReportSize - 1)])

        if version.major == 3 {
            // NEO caches the programming sequence in the arbitrator. Force the applet to refresh it
            // by writing an invalid scan map, which does nothing and is expected to be rejected.
            do {
                _ = try await sendAndReceive(slot: 0x12, data: Data(repeating: 0x63, count: 51))
            } catch {
                // A rejection here is the expected outcome, not a failure.
            }
        }
    }

    // MARK: - Exposed Operations

    /// Re-read the key's 6-byte status struct.
    public func readStatus() async throws(Error) -> Data {
        let report = try await receiveReport()
        let status = Data(report[1..<(otpFeatureReportSize - 1)])
        self.status = status
        return status
    }

    /// Abandons an in-flight touch-triggered command.
    ///
    /// The polling loop in `readFrame` observes this at its next suspension point, tells the key to
    /// drop its pending response, and throws ``OTPSessionError/cancelled(source:)``. Calling this
    /// while no command is running has no effect beyond arming the next one, so it is only ever
    /// handed out alongside a ``YubiOTP/Status/waitingForUser(cancel:)``.
    public func cancel() {
        isCancelled = true
    }

    /// Send a slot command and read the reply.
    ///
    /// - Parameters:
    ///   - slot: The slot/command code.
    ///   - data: The command payload, padded to 64 bytes. Must not exceed 64 bytes.
    ///   - onKeepalive: Called with each keep-alive code the key reports while it is busy —
    ///     ``keepaliveProcessing`` or ``keepaliveUserPresenceNeeded``, matching `on_keepalive` in
    ///     `yubikit.core.otp`.
    /// - Returns: For a read, the raw data response including its CRC trailer. For a configuration
    ///   write, the updated 6-byte status struct.
    @discardableResult
    public func sendAndReceive(
        slot: UInt8,
        data: Data? = nil,
        onKeepalive: (@Sendable (UInt8) -> Void)? = nil
    ) async throws(Error) -> Data {
        isCancelled = false
        let payload = data ?? Data()
        guard payload.count <= slotDataSize else {
            throw .illegalArgument("Payload of \(payload.count) bytes is too large for an OTP frame", source: .here())
        }

        // `_format_frame`: payload[64] ‖ slot ‖ crc16(payload) ‖ filler[3]. The CRC covers the
        // padded payload *only* — not the slot byte that follows it.
        var frame = payload
        frame.append(Data(count: slotDataSize - payload.count))
        let crc = frame.crc16
        frame.append(slot)
        frame.append(contentsOf: [UInt8(crc & 0xFF), UInt8(crc >> 8)])
        frame.append(Data(count: 3))

        let progSeq = try await sendFrame(Array(frame))
        return try await readFrame(previousProgrammingSequence: progSeq, onKeepalive: onKeepalive)
    }

    // MARK: - Framing

    /// Writes the 70-byte frame as ten 7-byte reports and returns the programming sequence
    /// observed beforehand, which is how a configuration write is later detected.
    private func sendFrame(_ frame: [UInt8]) async throws(Error) -> UInt8 {
        let progSeq = try await receiveReport()[statusOffsetProgSeq]

        for sequence in 0..<(frameSize / reportDataSize) {
            let start = sequence * reportDataSize
            let chunk = Array(frame[start..<(start + reportDataSize)])

            // All-zero chunks are skipped, except the first and last, which frame the transfer.
            let isEdge = sequence == 0 || sequence == 9
            guard isEdge || chunk.contains(where: { $0 != 0 }) else { continue }

            try await awaitReadyToWrite()
            try await sendReport(chunk + [slotWriteFlag | UInt8(sequence)])
        }

        return progSeq
    }

    /// Reads one reply: either chunked data terminated by a sequence-zero report, or a status
    /// struct whose programming sequence has advanced.
    private func readFrame(
        previousProgrammingSequence progSeq: UInt8,
        onKeepalive: (@Sendable (UInt8) -> Void)?
    ) async throws(Error) -> Data {
        var response = Data()
        var expectedSequence: UInt8 = 0
        var needsTouch = false

        while true {
            let report = try await receiveReport()
            let statusByte = report[otpFeatureReportSize - 1]

            if statusByte & respPendingFlag != 0 {
                let sequence = statusByte & sequenceMask
                if sequence == expectedSequence {
                    response.append(contentsOf: report[0..<reportDataSize])
                    expectedSequence += 1
                } else if sequence == 0 {
                    // Sequence restarted at zero: the transfer is complete.
                    try await resetState()
                    return response
                }
            } else if statusByte == 0 {
                guard response.isEmpty else {
                    throw .responseParseError("OTP data response ended mid-transfer", source: .here())
                }
                if isProgrammingSequenceUpdated(report, previous: progSeq) {
                    let status = Data(report[1..<(otpFeatureReportSize - 1)])
                    self.status = status
                    return status
                }
                if needsTouch {
                    throw .timeout(source: .here())
                }
                throw .commandRejected("The YubiKey rejected the slot command", source: .here())
            } else {
                // Busy. A pending touch is reported with RESP_TIMEOUT_WAIT_FLAG.
                if statusByte & respTimeoutWaitFlag != 0 {
                    needsTouch = true
                    onKeepalive?(keepaliveUserPresenceNeeded)
                    try await sleep(touchPollInterval)
                } else {
                    onKeepalive?(keepaliveProcessing)
                    try await sleep(processingPollInterval)
                }
                // Checked after the sleep, which is where `cancel()` gets a chance to run.
                if isCancelled {
                    isCancelled = false
                    try await resetState()
                    throw .cancelled(source: .here())
                }
            }
        }
    }

    /// A configuration write is acknowledged either by the programming sequence incrementing, or by
    /// it resetting to zero once the last configured slot has been deleted.
    private func isProgrammingSequenceUpdated(_ report: [UInt8], previous: UInt8) -> Bool {
        let next = report[statusOffsetProgSeq]
        if next == previous &+ 1 { return true }
        return next == 0 && previous > 0
            && report[statusOffsetTouchLow] & configSlotsProgrammedMask == 0
    }

    private func awaitReadyToWrite() async throws(Error) {
        for _ in 0..<readyPollAttempts {
            if try await receiveReport()[otpFeatureReportSize - 1] & slotWriteFlag == 0 { return }
            try await sleep(readyPollInterval)
        }
        throw .timeout(source: .here())
    }

    /// Tells the key to abandon any in-flight response.
    private func resetState() async throws(Error) {
        try await sendReport([UInt8](repeating: 0, count: reportDataSize) + [0xFF])
    }

    // MARK: - Transport helpers

    private func receiveReport() async throws(Error) -> [UInt8] {
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

    private func sendReport(_ report: [UInt8]) async throws(Error) {
        do {
            try await connection.send(Data(report))
        } catch {
            throw .otpConnectionError(error, source: .here())
        }
    }

    private func sleep(_ duration: Duration) async throws(Error) {
        do {
            try await Task.sleep(for: duration)
        } catch {
            throw .timeout(source: .here())
        }
    }
}

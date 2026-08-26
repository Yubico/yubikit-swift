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

// CCID instruction bytes (yubikit.yubiotp INS_CONFIG / INS_YK2_STATUS).
private let insConfig: UInt8 = 0x01
private let insStatus: UInt8 = 0x03

// The status struct is version[3] ‖ pgmSeq[1] ‖ configState[2, LE].
let statusOffsetProgrammingSequence = 3
let statusOffsetConfigState = 4
// A write acknowledgement is only read as far as the low config-state byte.
private let statusMinimumLength = 5

/// Protocol for interfaces that can drive the Yubico OTP application.
///
/// This abstracts the communication layer for OTP slot commands, so `YubiOTP.Session` can speak
/// both the keyboard HID frame protocol and CCID without knowing which it has. Implemented by
/// ``OTPInterface`` for the keyboard transport and ``SmartCardInterface`` for CCID.
///
/// Kept internal, like ``CBORInterface`` — the public surface is ``YubiOTP/Session``.
protocol YubiOTPInterface: Actor {

    /// The error type thrown by this interface.
    associatedtype Error: OTPSessionError

    /// The firmware version of the Yubico OTP application.
    var version: Version { get async }

    /// The status struct observed when the session opened.
    var initialStatus: [UInt8] { get async }

    /// Writes a configuration to a slot.
    ///
    /// - Returns: The updated status struct.
    /// - Throws: ``OTPSessionError/commandRejected(_:source:)`` if the key did not apply it.
    func writeConfig(command: UInt8, data: Data) async throws(Error) -> [UInt8]

    /// Runs a slot command that reads data, validating the transport's integrity check.
    func readData(
        slot: UInt8,
        data: Data,
        expectedLength: Int,
        onKeepalive: (@Sendable (UInt8) -> Void)?
    ) async throws(Error) -> Data

    /// Abandons an in-flight touch-triggered read.
    ///
    /// A no-op on transports that cannot be interrupted mid-command.
    func cancel() async
}

// MARK: - YubiOTPInterface Conformance (keyboard HID transport)

extension OTPInterface: YubiOTPInterface {

    var initialStatus: [UInt8] { Array(status) }

    func writeConfig(command: UInt8, data: Data) async throws(Error) -> [UInt8] {
        // The frame protocol tracks the programming sequence itself and only answers with a status
        // struct once it has advanced, so there is nothing further to check here.
        Array(try await sendAndReceive(slot: command, data: data))
    }

    func readData(
        slot: UInt8,
        data: Data,
        expectedLength: Int,
        onKeepalive: (@Sendable (UInt8) -> Void)?
    ) async throws(Error) -> Data {
        // The keyboard transport returns the payload followed by its CRC trailer.
        let response = try await sendAndReceive(slot: slot, data: data, onKeepalive: onKeepalive)
        guard response.count >= expectedLength + 2,
            response.prefix(expectedLength + 2).hasValidCRC16
        else {
            throw .responseParseError("Invalid CRC in OTP data response", source: .here())
        }
        return response.prefix(expectedLength)
    }
}

// MARK: - YubiOTPInterface Conformance (CCID transport)

extension SmartCardInterface: YubiOTPInterface where Error == YubiOTPSessionError {

    /// Parsed from the first three bytes of the status struct the OTP application returns from
    /// SELECT. Note this is a different encoding from the Management application, which answers
    /// with an ASCII version string.
    public var version: Version {
        get async { Version(withData: Data(selectResponse.prefix(3))) ?? Version(withData: Data([0, 0, 0]))! }
    }

    var initialStatus: [UInt8] { Array(selectResponse) }

    func writeConfig(command: UInt8, data: Data) async throws(Error) -> [UInt8] {
        // Read the sequence immediately before the write. Python's `_YubiOtpSmartCardBackend`
        // carries the previous value between calls to save a round trip; reading it back costs one
        // extra APDU per write and leaves the transport with no state of its own.
        let previous = try await readStatus()[statusOffsetProgrammingSequence]

        var response: Data = try await send(
            apdu: APDU(cla: 0, ins: insConfig, p1: command, p2: 0, command: data)
        )
        if response.isEmpty {
            // Some YubiKeys answer certain commands with no data; ask for the status.
            response = Data(try await readStatus())
        }
        let updated = Array(response)
        guard updated.count >= statusMinimumLength else {
            throw .responseParseError("Truncated OTP status struct", source: .here())
        }

        let current = updated[statusOffsetProgrammingSequence]
        if current == previous &+ 1 { return updated }
        if current == 0, previous > 0 {
            // Deleting the last configuration resets the sequence to zero.
            if updated[statusOffsetConfigState] & 0x1F == 0 { return updated }
            // These firmware revisions simply do not advance the programming state.
            if let version = Version(withData: Data(updated.prefix(3))),
                version >= Version("5.0.0")!, version < Version("5.4.3")!
            {
                return updated
            }
        }
        throw .commandRejected("The configuration was not updated", source: .here())
    }

    func readData(
        slot: UInt8,
        data: Data,
        expectedLength: Int,
        onKeepalive: (@Sendable (UInt8) -> Void)?
    ) async throws(Error) -> Data {
        // CCID checks integrity itself, so the applet returns exactly the payload.
        let response: Data = try await send(apdu: APDU(cla: 0, ins: insConfig, p1: slot, p2: 0, command: data))
        guard response.count == expectedLength else {
            throw .responseParseError(
                "Expected \(expectedLength) bytes from the OTP application, got \(response.count)",
                source: .here()
            )
        }
        return response
    }

    /// The CCID exchange is a single blocking APDU, exactly as in
    /// `_YubiOtpSmartCardBackend.send_and_receive`, so there is nothing to interrupt.
    func cancel() async {}

    // MARK: - Private

    /// Reads the status struct over CCID (`INS_YK2_STATUS`).
    private func readStatus() async throws(Error) -> [UInt8] {
        let response: Data = try await send(apdu: APDU(cla: 0, ins: insStatus, p1: 0, p2: 0))
        let bytes = Array(response)
        guard bytes.count >= statusMinimumLength else {
            throw .responseParseError("Truncated OTP status struct", source: .here())
        }
        return bytes
    }
}

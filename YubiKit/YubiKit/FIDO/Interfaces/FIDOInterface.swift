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
import OSLog

/// FIDO interface for CTAP HID communication
/// Handles authenticator communication over USB HID transport
public final actor FIDOInterface<Error: FIDOSessionError>: HasFIDOLogger {

    // MARK: - Properties
    public let connection: FIDOConnection
    public private(set) var version: Version = Version(withData: Data([0, 0, 0]))!

    // Private
    private(set) var capabilities: CTAP.Capabilities = []
    private(set) var protocolVersion: UInt8 = 0

    private var channelId: UInt32 = CTAP.CID_BROADCAST
    private let frameTimeout: Duration = .seconds(1.5)

    // MARK: - Initialization

    /// Initialize FIDO interface with the given connection
    /// Automatically performs CTAP INIT handshake
    init(connection: FIDOConnection) async throws(Error) {
        self.connection = connection
        try await initialize()
    }

    // MARK: - Internal API

    /// Test communication by sending data and receiving it back
    ///
    /// The PING command is used to verify that the HID transport is working correctly.
    /// The authenticator echoes back the exact data that was sent.
    ///
    /// - Parameter data: Data to send (and receive back). If nil, sends empty payload.
    /// - Returns: The echoed data from the authenticator
    /// - Throws: ``FIDOSessionError`` if the response doesn't match the sent data
    func ping(data: Data? = nil) async throws(Error) -> Data {
        let payload = data ?? Data()
        let response = try await sendAndReceive(cmd: Self.hidCommand(.ping), payload: payload)

        guard response == payload else {
            throw Error.responseParseError("PING response data mismatch", source: .here())
        }

        /* Fix trace: trace(message: "PING command completed: \(response.count) bytes echoed") */
        return response
    }

    /// Send wink command to the authenticator
    func wink() async throws(Error) {
        _ = try await sendAndReceive(cmd: Self.hidCommand(.wink), payload: nil)
        /* Fix trace: trace(message: "WINK command completed successfully") */
    }

    /// Lock the channel for exclusive access
    ///
    /// Prevents other channels from communicating with the device until the lock times out
    /// or is explicitly released. Useful for aggregated transactions that cannot be interrupted.
    ///
    /// - Parameter seconds: Lock duration in seconds (0-10). Values > 10 are capped at 10.
    ///   A value of 0 immediately releases the lock.
    func lock(seconds: UInt) async throws(Error) {
        let cappedSeconds = min(seconds, 10)
        let payload = Data([UInt8(cappedSeconds)])
        _ = try await sendAndReceive(cmd: Self.hidCommand(.lock), payload: payload)
        /* Fix trace: trace(message: "LOCK command completed: \(cappedSeconds) seconds") */
    }

    /// Release the channel lock
    ///
    /// Convenience method that immediately releases any active lock by calling ``lock(seconds:)`` with 0.
    func unlock() async throws(Error) {
        try await lock(seconds: 0)
    }

    /// Cancel any pending operation on this channel
    ///
    /// Aborts ongoing operations such as waiting for user interaction (touch prompt, PIN entry, etc.).
    /// Also prevents the authenticator from locking indefinitely if an incomplete multi-packet
    /// transaction has stalled.
    func cancel() async throws(Error) {
        _ = try await sendRequest(cmd: Self.hidCommand(.cancel), payload: nil)
    }

    /// Check if the authenticator supports a capability
    func supports(_ capability: CTAP.Capabilities) -> Bool {
        capabilities.contains(capability)
    }

    /// Send CBOR-encoded CTAP2 command and receive CBOR response
    ///
    /// This is the main entry point for CTAP2 protocol commands like authenticatorGetInfo,
    /// authenticatorMakeCredential, authenticatorGetAssertion, etc.
    ///
    /// - Parameter payload: CBOR-encoded command data (command byte + optional CBOR parameters)
    /// - Returns: Raw CBOR-encoded response data from the authenticator
    /// - Throws: ``FIDOSessionError`` if the command fails or CBOR capability is not supported
    func cbor(payload: Data) async throws(Error) -> Data {
        guard supports(.cbor) else {
            throw Error.featureNotSupported(source: .here())
        }
        return try await sendAndReceive(cmd: Self.hidCommand(.cbor), payload: payload)
    }

    /// Send CTAP command and wait for response
    /// Supports both single-frame and multi-frame messages.
    func sendAndReceive(cmd: UInt8, payload: Data?) async throws(Error) -> Data {
        /* Fix trace: trace(message: "sendAndReceive for cmd 0x\(String(format: "%02x", cmd))") */

        // Send request frames
        try await sendRequest(cmd: cmd, payload: payload)

        // Receive and parse response frames
        return try await receiveResponse(expectedCommand: cmd)
    }

    // MARK: - Private Implementation

    /// Perform CTAP INIT handshake to obtain channel ID and device info
    private func initialize() async throws(Error) {
        /* Fix trace: trace(message: "Starting FIDO interface initialization...") */

        // Generate random nonce for INIT
        let nonce = try generateRandomBytes(count: 8)
        /* Fix trace: trace(message: "Generated nonce: \(nonce.hexEncodedString)") */

        // Send INIT command and get response
        let response = try await sendAndReceive(cmd: Self.hidCommand(.`init`), payload: nonce)

        // INIT response format: nonce(8) + cid(4) + proto(1) + version(3) + caps(1)
        guard response.count >= 17 else {
            throw Error.initializationFailed("INIT response too short: \(response.count) bytes", source: .here())
        }

        // Check nonce was echoed back
        let responseNonce = response.subdata(in: 0..<8)
        guard responseNonce == nonce else {
            throw Error.initializationFailed("INIT nonce mismatch", source: .here())
        }

        // Get our assigned channel ID
        channelId = response.subdata(in: 8..<12).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }

        // Extract CTAPHID protocol version
        self.protocolVersion = response[12]

        // Extract device version info
        let versionBytes = response.subdata(in: 13..<16)
        self.version = Version(withData: versionBytes)!

        // Get capability flags
        self.capabilities = CTAP.Capabilities(rawValue: response[16])

        /* Fix trace: trace(message: "INIT successful") */
        /* Fix trace: trace(message: "Assigned channel ID: 0x\(String(format: "%08x", self.channelId))") */
        /* Fix trace: trace(message: "CTAPHID protocol version: \(self.protocolVersion)") */
        /* Fix trace: trace(message: "Device version: \(self.version)") */
        /* Fix trace: trace(message: "Capabilities: 0x\(String(format: "%02x", self.capabilities.rawValue))") */
    }

    /// Send CTAP request (init frame + continuation frames if needed)
    private func sendRequest(cmd: UInt8, payload: Data?) async throws(Error) {
        let payloadData = payload ?? Data()

        // Send init frame with first chunk of data
        let initFrame = buildInitFrame(channelId: channelId, command: cmd, payload: payloadData)
        do {
            try await connection.send(initFrame)
        } catch {
            throw .fidoConnectionError(error, source: .here())
        }
        /* Fix trace: trace(message: "Sent init frame (\(payloadData.count) total bytes)") */

        // If payload is larger than init frame can hold, send continuation frames
        var remainingData = payloadData.dropFirst(CTAP.INIT_DATA_SIZE)
        var sequence: UInt8 = 0

        while !remainingData.isEmpty {
            let contFrame = buildContinuationFrame(
                channelId: channelId,
                sequence: sequence,
                payload: Data(remainingData)
            )
            do {
                try await connection.send(contFrame)
            } catch {
                throw .fidoConnectionError(error, source: .here())
            }
            /* Fix trace: trace(message: "Sent continuation frame \(sequence)") */

            remainingData = remainingData.dropFirst(CTAP.CONT_DATA_SIZE)
            sequence += 1

            guard sequence < 128 else {
                throw Error.illegalArgument("Payload too large: exceeds maximum CTAP HID message size", source: .here())
            }
        }
    }

    /// Receive CTAP response (init frame + continuation frames if needed)
    /// Handles KEEPALIVE messages
    private func receiveResponse(expectedCommand: UInt8) async throws(Error) -> Data {
        // Loop to handle KEEPALIVE messages
        while true {
            // Read init frame with frame timeout
            let responseInitFrame: Data?
            do {
                responseInitFrame = try await withTimeout(frameTimeout) { try await self.connection.receive() }
            } catch {
                throw .fidoConnectionError(error as! FIDOConnectionError, source: .here())
            }

            guard let responseInitFrame = responseInitFrame else {
                throw .timeout(source: .here())
            }

            let (responseChannelId, responseCommand, payloadLength, initFrameData) = try parseInitFrame(
                responseInitFrame
            )

            // Validate channel ID
            guard responseChannelId == channelId else {
                throw Error.responseParseError("Invalid channel ID in response", source: .here())
            }

            // Handle KEEPALIVE - continue waiting
            if responseCommand == Self.hidCommand(.keepalive) {
                let status = initFrameData.first ?? 0
                /* Fix trace: trace(message: "KEEPALIVE status: \(status) (0x01=processing, 0x02=need touch, 0x03=need verification)") */
                continue  // Keep waiting for actual response
            }

            // Check if response is an error from the authenticator
            if responseCommand == Self.hidCommand(.error) {
                guard !initFrameData.isEmpty else {
                    throw Error.responseParseError("ERROR frame has no error code", source: .here())
                }
                let errorCode = initFrameData[0]
                let hidError = CTAP.HIDError.from(errorCode: errorCode)
                throw .hidError(hidError, source: .here())
            }

            // Validate response command matches request
            guard responseCommand == expectedCommand else {
                throw Error.responseParseError(
                    "Unexpected response command: expected 0x\(String(format: "%02x", expectedCommand)), received 0x\(String(format: "%02x", responseCommand))",
                    source: .here()
                )
            }

            /* Fix trace: trace(message: "Received init frame") */

            // Start building response payload with data from init frame
            var responsePayload = Data()
            responsePayload.append(initFrameData)

            // If more data expected, read continuation frames
            var expectedSequence: UInt8 = 0
            while responsePayload.count < payloadLength {
                let contFrame: Data?
                do {
                    contFrame = try await withTimeout(frameTimeout) { try await self.connection.receive() }
                } catch {
                    throw .fidoConnectionError(error as! FIDOConnectionError, source: .here())
                }

                guard let contFrame = contFrame else {
                    throw .timeout(source: .here())
                }
                /* Fix trace: trace(message: "Received continuation frame") */

                let (contChannelId, sequence, contData) = try parseContinuationFrame(contFrame)

                // Validate channel ID matches
                guard contChannelId == responseChannelId else {
                    throw Error.responseParseError("Channel ID mismatch in continuation frame", source: .here())
                }

                // Validate sequence number
                guard sequence == expectedSequence else {
                    throw Error.responseParseError(
                        "Sequence number mismatch: expected \(expectedSequence), got \(sequence)",
                        source: .here()
                    )
                }

                // Append data from continuation frame
                let bytesNeeded = payloadLength - responsePayload.count
                let bytesToTake = min(bytesNeeded, contData.count)
                responsePayload.append(contData.prefix(bytesToTake))

                expectedSequence += 1
            }

            /* Fix trace: trace(message: "Received complete response: \(responsePayload.count) bytes") */
            return responsePayload
        }
    }

    /// Build a HID initialization frame
    /// Init frame structure: CID(4) | CMD(1) | BCNT(2) | DATA(up to 57) | PADDING
    private func buildInitFrame(channelId: UInt32, command: UInt8, payload: Data) -> Data {
        var frame = Data()
        frame.reserveCapacity(CTAP.HID_PACKET_SIZE)

        // Channel ID (4 bytes, big-endian)
        var cidBE = channelId.bigEndian
        frame.append(Data(bytes: &cidBE, count: 4))

        // Command byte (1 byte)
        frame.append(command)

        // Byte count - total payload length (2 bytes, big-endian)
        var lengthBE = UInt16(payload.count).bigEndian
        frame.append(Data(bytes: &lengthBE, count: 2))

        // Payload data (up to 57 bytes for init frame)
        let dataToInclude = min(payload.count, CTAP.INIT_DATA_SIZE)
        if dataToInclude > 0 {
            frame.append(payload.prefix(dataToInclude))
        }

        // Pad to HID packet size (64 bytes) with zeros
        while frame.count < CTAP.HID_PACKET_SIZE {
            frame.append(0)
        }

        return frame
    }

    /// Build a HID continuation frame
    /// Continuation frame structure: CID(4) | SEQ(1) | DATA(up to 59) | PADDING
    private func buildContinuationFrame(channelId: UInt32, sequence: UInt8, payload: Data) -> Data {
        var frame = Data()
        frame.reserveCapacity(CTAP.HID_PACKET_SIZE)

        // Channel ID (4 bytes, big-endian)
        var cidBE = channelId.bigEndian
        frame.append(Data(bytes: &cidBE, count: 4))

        // Sequence number (1 byte, 0-127, no FRAME_INIT bit)
        frame.append(sequence)

        // Payload data (up to 59 bytes for continuation frame)
        let dataToInclude = min(payload.count, CTAP.CONT_DATA_SIZE)
        if dataToInclude > 0 {
            frame.append(payload.prefix(dataToInclude))
        }

        // Pad to HID packet size (64 bytes) with zeros
        while frame.count < CTAP.HID_PACKET_SIZE {
            frame.append(0)
        }

        return frame
    }

    /// Parse a HID initialization frame response
    /// Init frame structure: CID(4) | CMD(1) | BCNT(2) | DATA(up to 57)
    /// - Returns: (channelId, command, payloadLength, payloadData)
    private func parseInitFrame(
        _ frame: Data
    ) throws(Error) -> (
        channelId: UInt32, command: UInt8, payloadLength: Int, data: Data
    ) {
        guard frame.count == CTAP.HID_PACKET_SIZE else {
            throw Error.responseParseError(
                "Expected \(CTAP.HID_PACKET_SIZE) bytes, got \(frame.count)",
                source: .here()
            )
        }

        // Extract channel ID (bytes 0-3, big-endian)
        let channelId = frame.subdata(in: 0..<4).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }

        // Extract command byte (byte 4)
        let command = frame[4]

        // Extract payload length (bytes 5-6, big-endian)
        let payloadLength = Int(
            frame.subdata(in: 5..<7).withUnsafeBytes {
                $0.load(as: UInt16.self).bigEndian
            }
        )

        // Extract payload data (bytes 7+, up to payloadLength or end of init frame)
        let dataStart = CTAP.INIT_HEADER_SIZE
        let dataEnd = min(dataStart + payloadLength, frame.count)
        let data = frame.subdata(in: dataStart..<dataEnd)

        return (channelId: channelId, command: command, payloadLength: payloadLength, data: data)
    }

    /// Parse a HID continuation frame response
    /// Continuation frame structure: CID(4) | SEQ(1) | DATA(up to 59)
    /// - Returns: (channelId, sequence, payloadData)
    private func parseContinuationFrame(
        _ frame: Data
    ) throws(Error) -> (
        channelId: UInt32, sequence: UInt8, data: Data
    ) {
        guard frame.count == CTAP.HID_PACKET_SIZE else {
            throw Error.responseParseError(
                "Expected \(CTAP.HID_PACKET_SIZE) bytes, got \(frame.count)",
                source: .here()
            )
        }

        // Extract channel ID (bytes 0-3, big-endian)
        let channelId = frame.subdata(in: 0..<4).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }

        // Extract sequence number (byte 4, 0-127, no FRAME_INIT bit)
        let sequence = frame[4]
        guard sequence < 128 else {
            throw Error.responseParseError(
                "Invalid continuation frame sequence: \(sequence) (must be 0-127)",
                source: .here()
            )
        }

        // Extract payload data (bytes 5+)
        let dataStart = CTAP.CONT_HEADER_SIZE
        let data = frame.subdata(in: dataStart..<frame.count)

        return (channelId: channelId, sequence: sequence, data: data)
    }

    // MARK: - Utilities

    /// Convert CTAP command to HID command byte (with INIT frame bit set)
    static func hidCommand(_ command: CTAP.HID.Command) -> UInt8 {
        CTAP.FRAME_INIT | command.rawValue
    }

    /// Generate cryptographically secure random bytes
    private func generateRandomBytes(count: Int) throws(Error) -> Data {
        var randomData = Data(count: count)
        let result = randomData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw .cryptoError("Failed to generate random bytes for CTAP INIT", error: nil, source: .here())
        }
        return randomData
    }
}

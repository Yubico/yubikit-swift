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
/* public */ final actor FIDOInterface: HasFIDOLogger {

    // MARK: - Public Properties

    /* public */ let connection: FIDOConnection
    /* public */ private(set) var version: Version = Version(withData: Data([0, 0, 0]))!
    /* public */ private(set) var capabilities: UInt8 = 0

    // MARK: - Private Properties

    /// Channel ID for HID communication (starts as broadcast, gets assigned during init)
    private var channelId: UInt32 = 0xffff_ffff

    // MARK: - Constants

    /// Authenticator capability flags
    /* public */ struct Capability {
        /// Supports wink command
        /* public */ static let WINK: UInt8 = 0x01
        /// TODO: CTAP2 support
        /* public */ static let CBOR: UInt8 = 0x04
        /// TODO: Messages without user presence
        /* public */ static let NMSG: UInt8 = 0x08
    }

    /// CTAP HID command codes
    private static let TYPE_INIT: UInt8 = 0x80

    /// TODO: ping support
    private static let CTAPHID_PING = TYPE_INIT | 0x01
    /// TODO: U2F messages
    private static let CTAPHID_MSG = TYPE_INIT | 0x03
    /// TODO: channel lock
    private static let CTAPHID_LOCK = TYPE_INIT | 0x04
    /// Channel initialization command
    private static let CTAPHID_INIT = TYPE_INIT | 0x06
    /// Wink command (visual indicator)
    private static let CTAPHID_WINK = TYPE_INIT | 0x08
    /// TODO: CTAP2 CBOR support
    private static let CTAPHID_CBOR = TYPE_INIT | 0x10
    /// TODO: cancel operation
    private static let CTAPHID_CANCEL = TYPE_INIT | 0x11

    /// Error response command
    private static let CTAPHID_ERROR = TYPE_INIT | 0x3f
    /// Keep-alive message
    private static let CTAPHID_KEEPALIVE = TYPE_INIT | 0x3b

    // MARK: - Initialization

    /// Initialize FIDO interface with the given connection
    /// Automatically performs CTAP INIT handshake
    /* public */ init(connection: FIDOConnection) async throws {
        self.connection = connection
        try await initialize()
    }

    // MARK: - Public Methods

    /// Send CTAP command and wait for response
    /// TODO: multi-frame support, keepalive handling, continuation frames
    /* public */ func sendAndReceive(cmd: UInt8, payload: Data?) async throws -> Data {

        trace(message: "sendAndReceive for cmd 0x\(String(format: "%02x", cmd))")

        // Build CTAP frame: CID(4) + CMD(1) + LEN(2) + DATA + padding
        let toSend = payload ?? Data()
        var packet = Data()

        // INIT uses broadcast channel, others use assigned channel
        let cid = (cmd == Self.CTAPHID_INIT) ? 0xffff_ffff : channelId
        var channelIdBE = cid.bigEndian
        packet.append(Data(bytes: &channelIdBE, count: 4))
        packet.append(cmd)
        var lengthBE = UInt16(toSend.count).bigEndian
        packet.append(Data(bytes: &lengthBE, count: 2))

        if !toSend.isEmpty {
            packet.append(toSend)
        }

        // Pad to 64 bytes with zeros
        while packet.count < connection.mtu {
            packet.append(0)
        }

        // Set up receive before sending to avoid race conditions
        let receiveTask = Task { [connection] in
            try await connection.receive()
        }

        // Send command
        try await connection.send(packet)
        trace(message: "Sent \(packet.count) bytes: \(packet.hexEncodedString)")

        // Wait for response
        let responsePacket = try await receiveTask.value
        trace(message: "Got response: \(responsePacket.hexEncodedString)")

        // HID reports are always 64 bytes
        guard responsePacket.count == 64 else {
            throw CTAP.HIDError.parseError("Expected 64 bytes, got \(responsePacket.count)")
        }

        // Check response channel matches
        let responseChannel = responsePacket.subdata(in: 0..<4).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }

        // INIT responses can come from any channel
        if cmd != Self.CTAPHID_INIT {
            guard responseChannel == channelId else {
                throw CTAP.HIDError.invalidChannel
            }
        }

        // Verify response command
        let responseCmd = responsePacket[4]
        guard responseCmd == cmd else {
            if responseCmd == Self.CTAPHID_ERROR {
                let errorCode = responsePacket[7]
                throw CTAP.HIDError.from(errorCode: errorCode) ?? CTAP.UnknownError(errorCode: errorCode)
            }
            throw CTAP.HIDError.unexpectedResponse(expected: cmd, received: responseCmd)
        }

        // Extract the payload
        let responseLength = Int(
            responsePacket.subdata(in: 5..<7).withUnsafeBytes {
                $0.load(as: UInt16.self).bigEndian
            }
        )

        let payloadStart = 7
        let payloadEnd = min(payloadStart + responseLength, responsePacket.count)
        return responsePacket.subdata(in: payloadStart..<payloadEnd)
    }

    /// Send wink command to the authenticator
    /* public */ func wink() async throws {
        guard supports(Capability.WINK) else {
            throw CTAP.HIDError.invalidCmd(Self.CTAPHID_WINK)
        }

        _ = try await sendAndReceive(cmd: Self.CTAPHID_WINK, payload: nil)
        trace(message: "WINK command completed successfully")
    }

    /// Check if the authenticator supports a capability
    /* public */ func supports(_ capability: UInt8) -> Bool {
        (capabilities & capability) == capability
    }

    // MARK: - Private Methods

    private func initialize() async throws {
        trace(message: "Starting FIDO interface initialization...")

        // Generate random nonce for INIT
        let nonce = try generateRandomBytes(count: 8)
        trace(message: "Generated nonce: \(nonce.hexEncodedString)")

        // Send INIT command and get response
        let response = try await sendAndReceive(cmd: Self.CTAPHID_INIT, payload: nonce)

        // INIT response format: nonce(8) + cid(4) + proto(1) + version(3) + caps(1)
        guard response.count >= 17 else {
            throw CTAP.HIDError.parseError("INIT response too short: \(response.count) bytes")
        }

        // Check nonce was echoed back
        let responseNonce = response.subdata(in: 0..<8)
        guard responseNonce == nonce else {
            throw CTAP.HIDError.parseError("INIT nonce mismatch")
        }

        // Get our assigned channel ID
        channelId = response.subdata(in: 8..<12).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }

        // Extract device version info
        let versionBytes = response.subdata(in: 13..<16)
        self.version = Version(withData: versionBytes)!

        // Get capability flags
        self.capabilities = response[16]

        trace(message: "INIT successful")
        trace(message: "Assigned channel ID: 0x\(String(format: "%08x", self.channelId))")
        trace(message: "Version: \(self.version)")
        trace(message: "Capabilities: 0x\(String(format: "%02x", self.capabilities))")

        if (capabilities & Capability.WINK) != 0 {
            trace(message: "Device supports WINK")
        }
    }

    // MARK: - Private Helpers

    private func generateRandomBytes(count: Int) throws -> Data {
        var randomData = Data(count: count)
        let result = randomData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw CTAP.HIDError.other
        }
        return randomData
    }
}

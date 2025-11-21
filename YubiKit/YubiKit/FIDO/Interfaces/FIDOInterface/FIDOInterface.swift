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

    // Internal (accessible to extensions)
    private(set) var capabilities: CTAP.Capabilities = []
    private(set) var protocolVersion: UInt8 = 0

    var channelId: UInt32 = CTAP.CID_BROADCAST
    let frameTimeout: Duration = .seconds(1.5)

    // MARK: - Initialization

    /// Initialize FIDO interface with the given connection
    /// Automatically performs CTAP INIT handshake
    init(connection: FIDOConnection) async throws(Error) {
        self.connection = connection
        try await initialize()
    }

    // MARK: - Capabilities

    /// Check if the authenticator supports a capability
    func supports(_ capability: CTAP.Capabilities) -> Bool {
        capabilities.contains(capability)
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
}

// MARK: - KEEPALIVE Status Mapping

extension CTAP.Status {
    static func fromKeepAlive(
        statusByte: UInt8,
        cancel: @escaping @Sendable () async -> Void
    ) -> CTAP.Status<Response>? {
        switch statusByte {
        case 0x01:
            return .processing
        case 0x02:
            return .waitingForUserPresence(cancel: cancel)
        case 0x03:
            return .waitingForUserVerification(cancel: cancel)
        default:
            return nil  // Unknown status - caller should continue waiting
        }
    }
}

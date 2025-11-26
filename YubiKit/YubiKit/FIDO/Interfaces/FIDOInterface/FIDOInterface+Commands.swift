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

// MARK: - CTAP HID Commands

extension FIDOInterface {

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
    /// Sends a CANCEL command to abort ongoing operations such as waiting for user interaction.
    /// This is a one-way message - the authenticator will respond to the original command with
    /// a keepaliveCancel error rather than responding to the CANCEL command itself.
    ///
    /// - Throws: ``FIDOSessionError`` if sending the cancel command fails
    func cancel() async throws(Error) {
        try await sendRequest(cmd: Self.hidCommand(.cancel), payload: nil)
    }
}

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

/// A low-level transport connection to a FIDO device (YubiKey).
///
/// Use a connection to communicate with the YubiKey's FIDO authenticator via USB HID.
///
/// Protocol implemented in ``HIDFIDOConnection``.
public protocol FIDOConnection: Connection {

    /// Create a new FIDOConnection to the YubiKey.
    ///
    /// Initialize a FIDOConnection to get a connection to a YubiKey.
    /// The init method will wait until a connection to a YubiKey has been established.
    ///
    /// The init will throw with ``FIDOConnectionError/busy`` if there is an already established connection for the same
    /// resource.
    init() async throws(FIDOConnectionError)

    /// Maximum payload size (in bytes) for a single packet.
    var mtu: Int { get }

    /// Send one packet (≤ ``mtu`` bytes).
    ///
    /// - Parameter packet: The packet data to send (must not exceed ``mtu`` bytes).
    /// - Throws: ``FIDOConnectionError`` if transmission fails.
    func send(_ packet: Data) async throws(FIDOConnectionError)

    /// Receive one packet (≤ ``mtu`` bytes).
    ///
    /// - Returns: The received packet data.
    /// - Throws: ``FIDOConnectionError`` if reception fails.
    func receive() async throws(FIDOConnectionError) -> Data

    /// Create a new FIDOConnection to the YubiKey.
    ///
    /// Call this method to get a connection to a YubiKey. The method will wait
    /// until a connection to a YubiKey has been established and then return it.
    ///
    /// > Warning: Only one connection can exist at a time per device. If this method is called while
    /// another connection is active or pending to the same device, it will throw ``FIDOConnectionError/busy``.
    /// The existing connection must be closed first using ``close(error:)``.
    static func makeConnection() async throws(FIDOConnectionError) -> Self

    /// Close the current connection.
    ///
    /// - Parameter error: Optional error that caused the connection to close.
    func close(error: Error?) async

    /// Wait for the connection to close.
    ///
    /// - Returns: An error if the connection was closed due to an error, or `nil` if closed normally.
    func waitUntilClosed() async -> Error?
}

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
/// Works in terms of fixed-size packets (≤ `mtu`).
/* public */ protocol FIDOConnection: Connection {

    /// Maximum payload size (in bytes) for a single packet.
    var mtu: Int { get }

    /// Send one packet (≤ `mtu` bytes).
    func send(_ packet: Data) async throws

    /// Receive one packet (≤ `mtu` bytes).
    func receive() async throws -> Data

    /// Opens a new connection.
    static func connection() async throws -> FIDOConnection

    /// Close the current connection.
    func close(error: Error?) async

    /// Wait for the connection to close.
    func connectionDidClose() async -> Error?
}

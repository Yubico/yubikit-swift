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

// NEXTMAJOR: Remove this protocol.

/// Protocol for interfaces that can perform YubiKey management operations.
///
/// No type in the SDK conforms to this protocol. Management operations run through
/// ``Management/Session``, which selects the Management application before issuing them.
@available(
    *,
    deprecated,
    message: "No SDK type conforms to this protocol. Use Management.Session for management operations."
)
public protocol ManagementInterface: Actor {

    /// The error type thrown by this interface.
    associatedtype Error: SessionError

    /// The firmware version of the YubiKey.
    var version: Version { get async }

    /// Read a configuration page from the YubiKey.
    ///
    /// - Parameter page: The page number to read (0-based).
    /// - Returns: The raw TLV-encoded configuration data for the requested page.
    /// - Throws: An error if the read operation fails.
    func readConfig(page: UInt8) async throws -> Data

    /// Write configuration data to the YubiKey.
    ///
    /// - Parameter data: The configuration data to write.
    /// - Throws: An error if the write operation fails.
    func writeConfig(data: Data) async throws

    /// Perform a device reset (if supported by the transport).
    ///
    /// - Throws: An error if the reset operation fails or is not supported.
    func resetDevice() async throws
}

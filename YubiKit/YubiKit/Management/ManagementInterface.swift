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

/// Protocol for interfaces that can perform YubiKey management operations.
///
/// This protocol abstracts the communication layer for management operations,
/// allowing them to work over different transports (SmartCard via APDUs or FIDO via CTAP).
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

// MARK: - ManagementInterface Conformance
extension FIDOInterface: ManagementInterface {

    /// Read a configuration page from the YubiKey using vendor-specific CTAP commands.
    ///
    /// Uses the CTAP `readConfig` command (0x42) to read device configuration pages.
    ///
    /// - Parameter page: The page number to read (0-based).
    /// - Returns: The raw TLV-encoded configuration data for the requested page.
    public func readConfig(page: UInt8) async throws -> Data {
        let payload = Data([page])
        return try await sendAndReceive(cmd: Self.hidCommand(.readConfig), payload: payload)
    }

    /// Write configuration data to the YubiKey using vendor-specific CTAP commands.
    ///
    /// Uses the CTAP `writeConfig` command (0x43) to write device configuration.
    ///
    /// - Parameter data: The configuration data to write.
    public func writeConfig(data: Data) async throws {
        _ = try await sendAndReceive(cmd: Self.hidCommand(.writeConfig), payload: data)
    }

    /// Device reset is not supported over FIDO/CTAP transport.
    ///
    /// Device reset is only available over SmartCard (CCID) connections.
    public func resetDevice() async throws {
        throw Error.featureNotSupported(source: .here())
    }
}

// MARK: - ManagementInterface Conformance
extension SmartCardInterface: ManagementInterface {

    /// Read a configuration page from the YubiKey using SmartCard APDUs.
    ///
    /// - Parameter page: The page number to read (0-based).
    /// - Returns: The raw TLV-encoded configuration data for the requested page.
    public func readConfig(page: UInt8) async throws -> Data {
        let apdu = APDU(cla: 0, ins: 0x1d, p1: page, p2: 0)
        return try await send(apdu: apdu)
    }

    /// Write configuration data to the YubiKey using SmartCard APDUs.
    ///
    /// - Parameter data: The configuration data to write.
    public func writeConfig(data: Data) async throws {
        let apdu = APDU(cla: 0, ins: 0x1c, p1: 0, p2: 0, command: data)
        try await send(apdu: apdu)
    }

    /// Perform a device-wide reset using SmartCard APDUs.
    public func resetDevice() async throws {
        let apdu = APDU(cla: 0, ins: 0x1f, p1: 0, p2: 0)
        try await send(apdu: apdu)
    }

    /// The firmware version of the YubiKey, parsed from the select response.
    public var version: Version {
        get async {
            guard let version = Version(withManagementResult: selectResponse) else {
                return Version(withData: Data([0, 0, 0]))!
            }
            return version
        }
    }
}

// MARK: - Private helpers

extension Version {
    fileprivate init?(withManagementResult data: Data) {
        guard let resultString = String(bytes: data.bytes, encoding: .ascii) else { return nil }
        guard let versions = resultString.components(separatedBy: " ").last?.components(separatedBy: "."),
            versions.count == 3
        else {
            return nil
        }
        guard let major = UInt8(versions[0]), let minor = UInt8(versions[1]), let micro = UInt8(versions[2]) else {
            return nil
        }
        self.major = major
        self.minor = minor
        self.micro = micro
    }
}

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

import CryptoTokenKit
import Foundation
import OSLog

/// An interface to the Management application on the YubiKey.
///
/// Use the Management application to get information and configure a YubiKey.
/// Read more about the Management application on the
/// [Yubico developer website](https://developers.yubico.com/yubikey-manager/Config_Reference.html).
public final actor ManagementSession: SmartCardSession {
    public static let application: Application = .management

    public typealias Error = ManagementSessionError
    public typealias Feature = ManagementFeature

    public let connection: SmartCardConnection
    public let scpState: SCPState?

    /// The firmware version of the YubiKey.
    public let version: Version

    private init(
        connection: SmartCardConnection,
        scpKeyParams: SCPKeyParams? = nil
    ) async throws(ManagementSessionError) {

        // Select application
        let result: Data
        do {
            result = try await Self.selectApplication(using: connection)
        } catch {
            guard case let .failedResponse(responseStatus, source: _) = error else {
                throw error
            }
            switch responseStatus.status {
            case .invalidInstruction, .fileNotFound:
                throw .featureNotSupported()
            default:
                throw error
            }
        }

        // Set the version
        if let version = Version(withManagementResult: result) {
            self.version = version
        } else {
            throw .responseParseError("Failed to parse version from management response")
        }

        // Setup SCP if parameters provided
        if let scpKeyParams {
            scpState = try await Self.setupSCP(connection: connection, keyParams: scpKeyParams)
        } else {
            scpState = nil
        }

        self.connection = connection
    }

    /// Creates a new ManagementSession with the provided connection.
    /// - Parameters:
    ///   - connection: The smart card connection to use for this session.
    ///   - scpKeyParams: Optional SCP key parameters for authenticated communication.
    /// - Returns: A new ManagementSession instance.
    /// - Throws: ManagementSessionError if session creation fails.
    public static func makeSession(
        connection: SmartCardConnection,
        scpKeyParams: SCPKeyParams? = nil
    ) async throws(ManagementSessionError) -> ManagementSession {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
        // Create a new ManagementSession
        return try await ManagementSession(connection: connection, scpKeyParams: scpKeyParams)
    }

    /// Determines whether the session supports the specified feature.
    /// - Parameter feature: The feature to check for support.
    /// - Returns: true if the feature is supported, false otherwise.
    public func supports(_ feature: ManagementSession.Feature) async -> Bool {
        feature.isSupported(by: version)
    }

    /// Returns the DeviceInfo for the connected YubiKey.
    ///
    /// >Note: This functionality requires support for ``ManagementFeature/deviceInfo``, available on YubiKey 4.1 or later.
    public func getDeviceInfo() async throws(ManagementSessionError) -> DeviceInfo {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
        guard await self.supports(ManagementFeature.deviceInfo) else { throw .featureNotSupported() }

        var page: UInt8 = 0
        var hasMoreData = true
        var result = [TKTLVTag: Data]()
        while hasMoreData {
            let apdu = APDU(cla: 0, ins: 0x1d, p1: page, p2: 0)
            let data = try await process(apdu: apdu)
            guard let count = data.bytes.first, count > 0,
                let tlvs = TKBERTLVRecord.dictionaryOfData(from: data.subdata(in: 1..<data.count))
            else {
                throw .responseParseError("Failed to parse TLV data from device info")
            }
            Logger.management.debug(
                "\(String(describing: self).lastComponent), \(#function): page: \(page), data: \(data.hexEncodedString)"
            )
            result.merge(tlvs) { (_, new) in new }
            hasMoreData = tlvs[0x10] != nil
            page += 1
        }

        return DeviceInfo(withTlvs: result, fallbackVersion: version)
    }

    /// Write device config to a YubiKey 5 or later.
    ///
    /// >Note: This functionality requires support for ``ManagementFeature/deviceConfig``, available on YubiKey 5 or later.
    ///
    /// - Parameters:
    ///   - config: The device configuration to write.
    ///   - reboot: If true cause the YubiKey to immediately reboot, applying the new configuration.
    ///   - lockCode: The current lock code. Required if a configuration lock code is set.
    ///   - newLockCode: Changes or removes (if 16 byte all-zero) the configuration lock code.
    ///
    public func updateDeviceConfig(
        _ config: DeviceConfig,
        reboot: Bool,
        lockCode: Data? = nil,
        newLockCode: Data? = nil
    ) async throws(ManagementSessionError) {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
        guard await self.supports(ManagementFeature.deviceConfig) else { throw .featureNotSupported() }

        guard let data = config.data(reboot: reboot, lockCode: lockCode, newLockCode: newLockCode) else {
            throw .illegalArgument("Device configuration is too large (maximum 255 bytes)")
        }

        let apdu = APDU(cla: 0, ins: 0x1c, p1: 0, p2: 0, command: data)
        try await process(apdu: apdu)
    }

    /// Perform a device-wide reset in Bio Multi-protocol Edition devices.
    ///
    /// >Note: This functionality requires support for ``ManagementFeature/deviceReset``, available on YubiKey 5.6 or later.
    public func resetDevice() async throws(ManagementSessionError) {
        guard await self.supports(.deviceReset) else { throw .featureNotSupported() }
        let apdu = APDU(cla: 0, ins: 0x1f, p1: 0, p2: 0)
        try await process(apdu: apdu)
    }

    deinit {
        Logger.management.debug("\(String(describing: self).lastComponent), \(#function)")
    }

}

// MARK: - Private helpers

extension Version {
    internal init?(withManagementResult data: Data) {
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

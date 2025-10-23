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

// NEXTMAJOR: We could remove these
public typealias ManagementSession = ManagementSessionOverSmartCard
public typealias ManagementFeature = Management.Feature

public typealias ManagementSessionOverSmartCard = Management.Session<SmartCardInterface<ManagementSessionError>>
public typealias ManagementSessionOverFIDO = Management.Session<FIDOInterface<ManagementSessionError>>

public enum Management {

    /// Management session features.
    public enum Feature: SessionFeature, Sendable {

        /// Support for reading the DeviceInfo data from the YubiKey.
        case deviceInfo
        /// Support for writing DeviceConfig data to the YubiKey.
        case deviceConfig
        /// Support for device-wide reset
        case deviceReset

        public func isSupported(by version: Version) -> Bool {
            switch self {
            case .deviceInfo:
                return version >= Version("4.1.0")!
            case .deviceConfig:
                return version >= Version("5.0.0")!
            case .deviceReset:
                return version >= Version("5.6.0")!
            }
        }
    }

    /// A generic interface to the Management application on the YubiKey.
    ///
    /// Use the Management application to get information and configure a YubiKey.
    /// This generic version works with any interface that conforms to ``ManagementInterface``,
    /// allowing management operations over both SmartCard (APDU) and FIDO (CTAP) transports.
    ///
    /// Read more about the Management application on the
    /// [Yubico developer website](https://developers.yubico.com/yubikey-manager/Config_Reference.html).
    public final actor Session<I: ManagementInterface> where I.Error == ManagementSessionError {

        typealias Error = ManagementSessionError

        /// The underlying interface for communication (SmartCard or FIDO).
        public let interface: I

        /// The firmware version of the YubiKey.
        public let version: Version

        private init(interface: I) async {
            self.interface = interface
            self.version = await interface.version
        }

        /// Determines whether the session supports the specified feature.
        /// - Parameter feature: The feature to check for support.
        /// - Returns: true if the feature is supported, false otherwise.
        public func supports(_ feature: Management.Feature) async -> Bool {
            feature.isSupported(by: version)
        }

        /// Returns the DeviceInfo for the connected YubiKey.
        ///
        /// > Note: This functionality requires support for ``ManagementFeature/deviceInfo``, available on YubiKey 4.1 or later.
        public func getDeviceInfo() async throws -> DeviceInfo {
            guard await self.supports(ManagementFeature.deviceInfo) else {
                throw Error.featureNotSupported(source: .here())
            }

            var page: UInt8 = 0
            var hasMoreData = true
            var result = [TKTLVTag: Data]()

            while hasMoreData {
                let data = try await interface.readConfig(page: page)

                guard let count = data.bytes.first, count > 0,
                    let tlvs = TKBERTLVRecord.dictionaryOfData(from: data.subdata(in: 1..<data.count))
                else {
                    throw Error.responseParseError("Failed to parse TLV data from device info", source: .here())
                }
                result.merge(tlvs) { (_, new) in new }
                hasMoreData = tlvs[0x10] != nil
                page += 1
            }

            return DeviceInfo(withTlvs: result, fallbackVersion: version)
        }

        /// Write device config to a YubiKey 5 or later.
        ///
        /// > Note: This functionality requires support for ``ManagementFeature/deviceConfig``, available on YubiKey 5 or later.
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
        ) async throws {
            guard await self.supports(ManagementFeature.deviceConfig) else {
                throw Error.featureNotSupported(source: .here())
            }

            guard let data = config.data(reboot: reboot, lockCode: lockCode, newLockCode: newLockCode) else {
                throw Error.illegalArgument("Device configuration is too large (maximum 255 bytes)", source: .here())
            }

            try await interface.writeConfig(data: data)
        }

        /// Perform a device-wide reset in Bio Multi-protocol Edition devices.
        ///
        /// > Note: This functionality requires support for ``ManagementFeature/deviceReset``, available on YubiKey 5.6 or later.
        /// > Note: Device reset is only supported over SmartCard connections, not over FIDO/CTAP.
        public func resetDevice() async throws {
            guard await self.supports(.deviceReset) else {
                throw Error.featureNotSupported(source: .here())
            }
            try await interface.resetDevice()
        }
    }
}

extension Management.Session where I == SmartCardInterface<ManagementSessionError> {
    /// Creates a new Management session with the provided SmartCard interface.
    ///
    /// - Parameters:
    ///   - connection: The smart card connection to use for this session.
    ///   - scpKeyParams: Optional SCP key parameters for authenticated communication.
    /// - Returns: A new Management instance using SmartCard transport.
    /// - Throws: ``SmartCardManagementError`` if session creation fails.
    public static func makeSession(
        connection: SmartCardConnection,
        scpKeyParams: SCPKeyParams? = nil
    ) async throws -> Management.Session<SmartCardInterface<ManagementSessionError>> {
        // Create interface with application selection and optional SCP
        let interface = try await SmartCardInterface<Error>(
            connection: connection,
            application: .management,
            keyParams: scpKeyParams
        )

        return await .init(interface: interface)
    }
}

extension Management.Session where I == FIDOInterface<ManagementSessionError> {
    /// Creates a new Management session with the provided FIDO interface.
    ///
    /// - Parameter connection: The FIDO connection to use for this session.
    /// - Returns: A new Management instance using FIDO/CTAP transport.
    /// - Throws: ``FIDOManagementError`` if session creation fails.
    public static func makeSession(
        connection: FIDOConnection
    ) async throws -> Management.Session<FIDOInterface<ManagementSessionError>> {
        // Create FIDO interface
        let interface = try await FIDOInterface<Error>(connection: connection)
        return await .init(interface: interface)
    }
}

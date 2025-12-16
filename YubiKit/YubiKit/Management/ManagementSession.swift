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

// NEXTMAJOR: Remove these typealiases
@available(*, deprecated, renamed: "Management.Session")
public typealias ManagementSession = Management.Session

@available(*, deprecated, renamed: "Management.Feature")
public typealias ManagementFeature = Management.Feature

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

    /// An interface to the Management application on the YubiKey.
    ///
    /// Use the Management application to get information and configure a YubiKey.
    /// Supports management operations over both SmartCard (APDU) and FIDO (CTAP) transports.
    ///
    /// Read more about the Management application on the
    /// [Yubico developer website](https://developers.yubico.com/yubikey-manager/Config_Reference.html).
    // NEXTMAJOR: Remove SmartCardSession conformance
    public final actor Session: SmartCardSession {

        public typealias Error = ManagementSessionError

        /// The underlying interface for communication (SmartCard or FIDO).
        private let interface: Interface

        /// The firmware version of the YubiKey.
        public let version: Version

        /// Determines whether the session supports the specified feature.
        /// - Parameter feature: The feature to check for support.
        /// - Returns: true if the feature is supported, false otherwise.
        public func supports(_ feature: Management.Feature) async -> Bool {
            feature.isSupported(by: version)
        }

        /// Returns the DeviceInfo for the connected YubiKey.
        ///
        /// > Note: This functionality requires support for ``Management/Feature/deviceInfo``, available on YubiKey 4.1 or later.
        public func getDeviceInfo() async throws -> DeviceInfo {
            guard await self.supports(.deviceInfo) else {
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
        /// > Note: This functionality requires support for ``Management/Feature/deviceConfig``, available on YubiKey 5 or later.
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
            guard await self.supports(.deviceConfig) else {
                throw Error.featureNotSupported(source: .here())
            }

            guard let data = config.data(reboot: reboot, lockCode: lockCode, newLockCode: newLockCode) else {
                throw Error.illegalArgument("Device configuration is too large (maximum 255 bytes)", source: .here())
            }

            try await interface.writeConfig(data: data)
        }

        /// Perform a device-wide reset in Bio Multi-protocol Edition devices.
        ///
        /// > Note: This functionality requires support for ``Management/Feature/deviceReset``, available on YubiKey 5.6 or later.
        /// > Note: Device reset is only supported over SmartCard connections, not over FIDO/CTAP.
        public func resetDevice() async throws {
            guard await self.supports(.deviceReset) else {
                throw Error.featureNotSupported(source: .here())
            }
            try await interface.resetDevice()
        }

        /// Creates a new Management session with the provided SmartCard connection.
        ///
        /// - Parameters:
        ///   - connection: The smart card connection to use for this session.
        ///   - scpKeyParams: Optional SCP key parameters for authenticated communication.
        /// - Returns: A new Management.Session instance.
        /// - Throws: ``ManagementSessionError`` if session creation fails.
        public static func makeSession(
            connection: SmartCardConnection,
            scpKeyParams: SCPKeyParams? = nil
        ) async throws(ManagementSessionError) -> Self {
            let smartCardInterface = try await SmartCardInterface<Error>(
                connection: connection,
                application: .management,
                keyParams: scpKeyParams
            )
            return await .init(interface: Interface(interface: smartCardInterface))
        }

        /// Creates a new Management session with the provided FIDO connection.
        ///
        /// - Parameter connection: The FIDO connection to use for this session.
        /// - Returns: A new Management.Session instance.
        /// - Throws: ``ManagementSessionError`` if session creation fails.
        public static func makeSession(
            connection: FIDOConnection
        ) async throws(ManagementSessionError) -> Self {
            let fidoInterface = try await FIDOInterface<Error>(connection: connection)
            return await .init(interface: Interface(interface: fidoInterface))
        }

        private init(interface: Interface) async {
            self.interface = interface
            self.version = await interface.version
            self.scpState = await interface.scpState
            self.smartCardConnection = await interface.smartCardConnection
        }

        // MARK: - SmartCardSession conformance (NEXTMAJOR: Remove)
        // These properties exist only for backwards compatibility with the deprecated
        // SmartCardSession protocol. They use `nonisolated` to satisfy the protocol's sync requirements.
        // The `connection` property will crash if the session was created with a FIDO connection.

        public static let application: Application = .management

        public nonisolated let scpState: SCPState?

        private nonisolated let smartCardConnection: SmartCardConnection?

        /// The SmartCard connection used to create this session.
        ///
        /// - Important: This property will crash if the session was created with a FIDO connection.
        @available(*, deprecated, message: "Avoid accessing the underlying connection directly")
        public nonisolated var connection: SmartCardConnection {
            smartCardConnection!
        }
    }
}

// MARK: - Interface (Internal Transport Abstraction)

extension Management.Session {
    /// Internal actor that abstracts over the underlying transport (SmartCard or FIDO).
    ///
    /// This allows `Management.Session` to be a concrete type while supporting multiple transports.
    internal actor Interface {
        private enum Kind {
            case smartCard(SmartCardInterface<ManagementSessionError>)
            case fido(FIDOInterface<ManagementSessionError>)
        }

        private let kind: Kind

        init(interface: SmartCardInterface<ManagementSessionError>) {
            self.kind = .smartCard(interface)
        }

        init(interface: FIDOInterface<ManagementSessionError>) {
            self.kind = .fido(interface)
        }

        var version: Version {
            get async {
                switch kind {
                case let .smartCard(i):
                    return await i.version
                case let .fido(i):
                    return await i.version
                }
            }
        }

        func readConfig(page: UInt8) async throws -> Data {
            switch kind {
            case let .smartCard(i):
                return try await i.readConfig(page: page)
            case let .fido(i):
                return try await i.readConfig(page: page)
            }
        }

        func writeConfig(data: Data) async throws {
            switch kind {
            case let .smartCard(i):
                try await i.writeConfig(data: data)
            case let .fido(i):
                try await i.writeConfig(data: data)
            }
        }

        func resetDevice() async throws {
            switch kind {
            case let .smartCard(i):
                try await i.resetDevice()
            case let .fido(i):
                try await i.resetDevice()
            }
        }

        var smartCardConnection: SmartCardConnection? {
            switch kind {
            case let .smartCard(i):
                return i.connection
            case .fido:
                return nil
            }
        }

        var scpState: SCPState? {
            switch kind {
            case let .smartCard(i):
                return i.scpState
            case .fido:
                return nil
            }
        }
    }
}
